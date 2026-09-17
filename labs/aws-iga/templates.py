"""Generate reviewable CloudFormation for the single-account Exercise A."""
import json
from pathlib import Path


def ref(name):
    return {"Ref": name}


def arn(name):
    return {"Fn::GetAtt": [name, "Arn"]}


def sub(value):
    return {"Fn::Sub": value}


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions, resources, **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


def generate(lab, account, primary, secondary, owner, expiry, expired):
    tags = lambda **kw: [{"Key": k, "Value": str(v)} for k, v in {"LabId": lab, **kw}.items()]
    r = {}

    def add(name, kind, props, **extra):
        r[name] = {"Type": "AWS::" + kind, "Properties": props, **extra}
        return ref(name)

    def role(name, display, service=None, principal=None, extra_tags=None):
        principal = {"Service": service} if service else {"AWS": principal}
        trust = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
        if service == "pods.eks.amazonaws.com":
            trust["Action"] = ["sts:AssumeRole", "sts:TagSession"]
            trust["Condition"] = {"StringEquals": {
                "aws:RequestTag/kubernetes-namespace": "operations",
                "aws:RequestTag/kubernetes-service-account": "reconcile-sa",
                "aws:RequestTag/eks-cluster-name": lab + "-eks"}}
        add(name, "IAM::Role", {"RoleName": lab + "-" + display,
            "AssumeRolePolicyDocument": doc(trust),
            "Tags": tags(Fixture=name, **(extra_tags or {}))})

    def policy(name, target, *statements, managed=False):
        props = {"PolicyDocument": doc(*statements)}
        if managed:
            props.update(ManagedPolicyName=lab + "-" + name, Roles=[ref(target)])
            add(name, "IAM::ManagedPolicy", props)
        else:
            props.update(PolicyName=name, Roles=[ref(target)])
            add(name, "IAM::Policy", props)

    def network(prefix, cidr):
        add(prefix + "VPC", "EC2::VPC", {"CidrBlock": cidr, "EnableDnsSupport": True,
            "EnableDnsHostnames": True, "Tags": tags(Name=lab + "-vpc")})
        add(prefix + "IGW", "EC2::InternetGateway", {"Tags": tags()})
        add(prefix + "Attach", "EC2::VPCGatewayAttachment", {"VpcId": ref(prefix + "VPC"), "InternetGatewayId": ref(prefix + "IGW")})
        add(prefix + "Routes", "EC2::RouteTable", {"VpcId": ref(prefix + "VPC"), "Tags": tags()})
        add(prefix + "DefaultRoute", "EC2::Route", {"RouteTableId": ref(prefix + "Routes"),
            "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": ref(prefix + "IGW")}, DependsOn=prefix + "Attach")
        for n in range(2):
            add(prefix + f"Subnet{n}", "EC2::Subnet", {"VpcId": ref(prefix + "VPC"),
                "CidrBlock": cidr.split(".")[0] + "." + cidr.split(".")[1] + f".{n}.0/24",
                "AvailabilityZone": {"Fn::Select": [n, {"Fn::GetAZs": ""}]},
                "MapPublicIpOnLaunch": True, "Tags": tags()})
            add(prefix + f"SubnetRoute{n}", "EC2::SubnetRouteTableAssociation", {
                "SubnetId": ref(prefix + f"Subnet{n}"), "RouteTableId": ref(prefix + "Routes")})
        add(prefix + "SecurityGroup", "EC2::SecurityGroup", {"GroupDescription": "Lab: no inbound rules",
            "VpcId": ref(prefix + "VPC"), "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}], "Tags": tags()})

    for name, suffix in [("BKT01", "attachments"), ("BKT02", "finance"), ("Audit", "audit")]:
        add(name, "S3::Bucket", {"BucketName": f"{lab}-{account}-{suffix}",
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True,
                "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            "BucketEncryption": {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
            "Tags": tags(Fixture=name)})
    for name, key, suffix in [("D01", "ticket_id", "tickets"), ("D02", "refund_id", "refunds")]:
        add(name, "DynamoDB::Table", {"TableName": lab + "-" + suffix, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": key, "KeyType": "HASH"}], "Tags": tags(Fixture=name)})
    for name, suffix in [("K01", "reports"), ("K02", "restricted")]:
        add(name, "KMS::Key", {"Description": lab + " synthetic " + suffix, "PendingWindowInDays": 7,
            "EnableKeyRotation": True, "KeyPolicy": doc(allow("kms:*", "*", Principal={"AWS": f"arn:aws:iam::{account}:root"})),
            "Tags": tags(Fixture=name)})
        add(name + "Alias", "KMS::Alias", {"AliasName": f"alias/{lab}-{suffix}", "TargetKeyId": ref(name)})
    r["BKT02"]["Properties"]["BucketEncryption"] = {"ServerSideEncryptionConfiguration": [
        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": arn("K01")}}]}
    for name, suffix in [("S01", "refund-sandbox"), ("S02", "legacy-summary")]:
        add(name, "SecretsManager::Secret", {"Name": lab + "/" + suffix,
            "SecretString": "NOT_A_REAL_TOKEN_" + name, "Tags": tags(Fixture=name)})

    for name, display, service in [
        ("R01", "SupportOrchestratorRole", "lambda.amazonaws.com"),
        ("R02", "SharedToolRole", "lambda.amazonaws.com"),
        ("R03", "RefundTaskRole", "ecs-tasks.amazonaws.com"),
        ("R04", "RefundExecutionRole", "ecs-tasks.amazonaws.com"),
        ("R05", "ReconcilePodRole", "pods.eks.amazonaws.com"),
        ("R08", "ShadowExportRole", "ec2.amazonaws.com"),
        ("R09", "LegacySummaryRole", "lambda.amazonaws.com"),
        ("R12", "SupportAppRole", "lambda.amazonaws.com")]:
        role(name, display, service)
    role("R06", "ReportsReaderRole", principal=arn("R05"), extra_tags={"Team": "operations"})
    # Pod Identity's transitive session tags continue through this role chain.
    r["R06"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Action"] = ["sts:AssumeRole", "sts:TagSession"]
    role("R07", "RefundWriterRole", principal=arn("R02"))
    role("R10", "LabWorkloadReadRole", principal=arn("R12"))
    role("R11", "LabDataReadRole", principal=arn("R12"))
    add("B01", "IAM::ManagedPolicy", {"ManagedPolicyName": lab + "-B01", "PolicyDocument": doc(
        allow("*", "*"), {"Effect": "Deny", "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"], "Resource": arn("D01")})})
    r["R02"]["Properties"]["PermissionsBoundary"] = ref("B01")
    policy("P01", "R02", allow(["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem"], arn("D01")), managed=True)
    policy("P02", "R02", allow("sts:AssumeRole", arn("R07")))
    policy("P03", "R02", allow("s3:GetObject", [sub("${BKT01.Arn}/attachments/*"), sub("${BKT01.Arn}/sandbox/probe.txt")]), managed=True)
    policy("P04", "R02", allow("s3:GetObject", sub("${BKT01.Arn}/sandbox/probe.txt")))
    policy("P05", "R02", allow("s3:GetObject", sub("${BKT02.Arn}/finance/*")))
    policy("P06", "R06", allow("s3:GetObject", sub("${BKT02.Arn}/reports/*"),
        Condition={"StringEquals": {"aws:PrincipalTag/Team": "operations"}}), managed=True)
    policy("P07", "R06", allow("kms:Decrypt", arn("K01")))
    policy("P08", "R06", allow("s3:DeleteObject", sub("${BKT02.Arn}/reports/*")))
    function_arn = lambda suffix: f"arn:aws:lambda:{primary}:{account}:function:{lab}-{suffix}"
    policy("P09", "R01", allow("lambda:InvokeFunction", function_arn("ticket-tools")))
    policy("RefundInvoke", "R03", allow("lambda:InvokeFunction", function_arn("refund-tools")))
    r["R04"]["Properties"]["ManagedPolicyArns"] = ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]
    policy("ReportsAssume", "R05", allow(["sts:AssumeRole", "sts:TagSession"], arn("R06")))
    policy("RefundWrite", "R07", allow("dynamodb:PutItem", arn("D02")))
    policy("ShadowRead", "R08", allow("s3:GetObject", sub("${BKT01.Arn}/attachments/*")))
    policy("LegacyRead", "R09", allow("s3:GetObject", sub("${BKT01.Arn}/attachments/*")), allow("secretsmanager:GetSecretValue", ref("S02")))
    policy("WorkloadRead", "R10", allow("s3:ListBucket", arn("BKT01")))
    policy("DataRead", "R11", allow("dynamodb:DescribeTable", arn("D02")))
    policy("AppCalls", "R12", allow("lambda:InvokeFunction", function_arn("support-orchestrator") + ":prod"),
        allow("sts:AssumeRole", [arn("R10"), arn("R11")]))
    add("FinancePolicy", "S3::BucketPolicy", {"Bucket": ref("BKT02"), "PolicyDocument": doc(
        {"Sid": "RP01", "Effect": "Deny", "Principal": {"AWS": arn("R02")}, "Action": "s3:GetObject", "Resource": sub("${BKT02.Arn}/finance/*")},
        {"Sid": "RP03", "Effect": "Deny", "Principal": {"AWS": arn("R06")}, "Action": "s3:DeleteObject", "Resource": sub("${BKT02.Arn}/*")})})
    add("U01", "IAM::User", {"UserName": lab + "-legacy-export-bot", "Tags": tags(Fixture="U01"),
        "Policies": [{"PolicyName": "LegacyProbe", "PolicyDocument": doc(allow("s3:GetObject", sub("${BKT01.Arn}/sandbox/probe.txt")))}]})
    logarn = f"arn:aws:logs:{primary}:{account}:log-group:/aws/lambda/{lab}-*:*"
    for role_id in ["R01", "R02", "R09", "R12"]:
        policy("Logs" + role_id, role_id, allow(["logs:CreateLogStream", "logs:PutLogEvents"], logarn))
    code = Path(__file__).with_name("runtime.py").read_text()
    common = {"MODEL_MODE": "stub", "TICKETS": ref("D01"), "REFUNDS": ref("D02"),
        "ATTACHMENTS": ref("BKT01"), "FINANCE": ref("BKT02"), "REFUND_ROLE": arn("R07"),
        "TICKET_TOOL": lab + "-ticket-tools", "ORCHESTRATOR": lab + "-support-orchestrator", "LEGACY_SECRET": ref("S02")}
    for logical, suffix, mode, role_id, agent in [
        ("Orchestrator", "support-orchestrator", "orchestrator", "R01", "A01"),
        ("TicketTools", "ticket-tools", "ticket", "R02", "L01"),
        ("RefundTools", "refund-tools", "refund", "R02", "L02"),
        ("Legacy", "legacy-summary", "legacy", "R09", "A05"),
        ("App", "support-app", "app", "R12", "L03")]:
        add(logical + "Log", "Logs::LogGroup", {"LogGroupName": "/aws/lambda/" + lab + "-" + suffix, "RetentionInDays": 7})
        env = {**common, "FIXTURE_MODE": mode}
        if mode == "app":
            env["LAB_AUTH_KEY"] = ref("LabAuthKey")
        add(logical, "Lambda::Function", {"FunctionName": lab + "-" + suffix, "Runtime": "python3.12",
            "Handler": "index.handler", "Timeout": 45, "MemorySize": 128, "Role": arn(role_id),
            "Code": {"ZipFile": code}, "Environment": {"Variables": env},
            "Tags": tags(AgentId=agent, Environment="scripted-lab", ExpiresAt=expired if agent == "A05" else expiry,
                         **({} if agent == "A05" else {"Owner": "priya@acme.example" if agent == "A01" else owner}))}, DependsOn=logical + "Log")

    network("Main", "10.91.0.0/16")
    add("ECSLog", "Logs::LogGroup", {"LogGroupName": lab + "-ecs", "RetentionInDays": 7})
    add("ECSCluster", "ECS::Cluster", {"ClusterName": lab + "-ecs", "Tags": tags()})
    add("ECSTask", "ECS::TaskDefinition", {"Family": lab + "-refund-agent", "Cpu": "256", "Memory": "512",
        "NetworkMode": "awsvpc", "RequiresCompatibilities": ["FARGATE"], "TaskRoleArn": arn("R03"), "ExecutionRoleArn": arn("R04"),
        "ContainerDefinitions": [{"Name": "refund-agent", "Image": "public.ecr.aws/aws-cli/aws-cli:latest", "Essential": True,
            "EntryPoint": ["/bin/sh", "-c"], "Command": [f"while true; do aws lambda invoke --region {primary} --function-name {lab}-refund-tools /tmp/result.json && cat /tmp/result.json; sleep 3600; done"],
            "LogConfiguration": {"LogDriver": "awslogs", "Options": {"awslogs-group": ref("ECSLog"), "awslogs-region": primary, "awslogs-stream-prefix": "fixture"}}}],
        "Tags": tags(AgentId="A02", Owner=owner, ExpiresAt=expiry)})
    add("ECSService", "ECS::Service", {"Cluster": ref("ECSCluster"), "ServiceName": lab + "-refund-agent", "DesiredCount": 1,
        "LaunchType": "FARGATE", "TaskDefinition": ref("ECSTask"),
        "DeploymentConfiguration": {"DeploymentCircuitBreaker": {"Enable": True, "Rollback": True}},
        "NetworkConfiguration": {"AwsvpcConfiguration": {"AssignPublicIp": "ENABLED", "Subnets": [ref("MainSubnet0")], "SecurityGroups": [ref("MainSecurityGroup")]}}},
        DependsOn=["MainDefaultRoute", "MainSubnetRoute0", "RefundInvoke"])
    role("ClusterRole", "EKSClusterRole", "eks.amazonaws.com")
    r["ClusterRole"]["Properties"]["ManagedPolicyArns"] = ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    role("NodeRole", "EKSNodeRole", "ec2.amazonaws.com")
    r["NodeRole"]["Properties"]["ManagedPolicyArns"] = ["arn:aws:iam::aws:policy/" + name for name in
        ["AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryPullOnly", "AmazonEKS_CNI_Policy"]]
    add("EKS", "EKS::Cluster", {"Name": lab + "-eks", "RoleArn": arn("ClusterRole"),
        "AccessConfig": {"AuthenticationMode": "API", "BootstrapClusterCreatorAdminPermissions": True},
        "ResourcesVpcConfig": {"SubnetIds": [ref("MainSubnet0"), ref("MainSubnet1")], "EndpointPrivateAccess": True,
            "EndpointPublicAccess": True}, "UpgradePolicy": {"SupportType": "STANDARD"}, "Tags": tags()})
    add("Nodes", "EKS::Nodegroup", {"ClusterName": ref("EKS"), "NodeRole": arn("NodeRole"), "AmiType": "AL2023_x86_64_STANDARD",
        "InstanceTypes": ["t3.medium"], "CapacityType": "ON_DEMAND", "ScalingConfig": {"DesiredSize": 1, "MinSize": 1, "MaxSize": 1},
        "Subnets": [ref("MainSubnet0"), ref("MainSubnet1")], "Tags": {"LabId": lab}},
        DependsOn=["MainDefaultRoute", "MainSubnetRoute0", "MainSubnetRoute1"])
    add("PodIdentityAgent", "EKS::Addon", {"ClusterName": ref("EKS"), "AddonName": "eks-pod-identity-agent"}, DependsOn="Nodes")
    add("PodAssociation", "EKS::PodIdentityAssociation", {"ClusterName": ref("EKS"), "Namespace": "operations",
        "ServiceAccount": "reconcile-sa", "RoleArn": arn("R05"), "Tags": tags(Fixture="I04")})

    trail_arn = f"arn:aws:cloudtrail:{primary}:{account}:trail/{lab}-trail"
    add("AuditPolicy", "S3::BucketPolicy", {"Bucket": ref("Audit"), "PolicyDocument": doc(
        allow("s3:GetBucketAcl", arn("Audit"), Principal={"Service": "cloudtrail.amazonaws.com"}, Condition={"StringEquals": {"aws:SourceArn": trail_arn}}),
        allow("s3:PutObject", sub("${Audit.Arn}/AWSLogs/${AWS::AccountId}/*"), Principal={"Service": "cloudtrail.amazonaws.com"},
              Condition={"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}))})
    selectors = [{"Name": "Management", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]
    for name, typ, resources in [("Objects", "AWS::S3::Object", [sub("${BKT01.Arn}/"), sub("${BKT02.Arn}/")]),
        ("TicketsOnly", "AWS::DynamoDB::Table", [arn("D01")]),
        ("Functions", "AWS::Lambda::Function", [function_arn(s) for s in ["support-app", "support-orchestrator", "ticket-tools", "refund-tools", "legacy-summary"]])]:
        selectors.append({"Name": name, "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": [typ]}, {"Field": "resources.ARN", "StartsWith": resources}]})
    add("Trail", "CloudTrail::Trail", {"TrailName": lab + "-trail", "S3BucketName": ref("Audit"), "IsLogging": True,
        "IsMultiRegionTrail": True, "IncludeGlobalServiceEvents": True, "EnableLogFileValidation": True,
        "AdvancedEventSelectors": selectors, "Tags": tags()}, DependsOn="AuditPolicy")
    outputs = {name: {"Value": ref(name)} for name in ["BKT01", "BKT02", "Audit", "D01", "D02", "S01", "S02", "U01", "EKS", "ECSCluster", "ECSTask", "P03"]}
    outputs.update({name: {"Value": arn(name)} for name in ["K01", "K02"] + [f"R{n:02}" for n in range(1, 13)]})
    main = {"AWSTemplateFormatVersion": "2010-09-09", "Description": "AuthSec Exercise A synthetic sandbox; paid resources; no native AI agent",
        "Parameters": {"LabAuthKey": {"Type": "String", "NoEcho": True, "MinLength": 32}}, "Resources": r, "Outputs": outputs}

    r = {}
    network("Shadow", "10.92.0.0/16")
    add("Profile", "IAM::InstanceProfile", {"InstanceProfileName": lab + "-ShadowExportProfile", "Roles": [lab + "-ShadowExportRole"]})
    boot = f"""#!/bin/bash
set -eu
dnf install -y unzip
curl -fsS https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install --update
for n in $(seq 1 30); do
  /usr/local/bin/aws s3api get-object --region {primary} --bucket {lab}-{account}-attachments --key attachments/451.txt /tmp/attachment.txt && break
  sleep 30
done
"""
    add("ShadowInstance", "EC2::Instance", {"ImageId": ref("Image"), "InstanceType": "t3.micro",
        "SubnetId": ref("ShadowSubnet0"), "SecurityGroupIds": [ref("ShadowSecurityGroup")], "IamInstanceProfile": ref("Profile"),
        "MetadataOptions": {"HttpTokens": "required"}, "UserData": {"Fn::Base64": boot},
        "Tags": tags(Name="support-app", Fixture="A04", Environment="scripted-lab")}, DependsOn=["ShadowDefaultRoute", "ShadowSubnetRoute0"])
    shadow = {"AWSTemplateFormatVersion": "2010-09-09", "Description": "AuthSec Exercise A secondary-region shadow workload",
        "Parameters": {"Image": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
            "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}}, "Resources": r,
        "Outputs": {"ShadowInstance": {"Value": ref("ShadowInstance")}}}
    return main, shadow


if __name__ == "__main__":
    import sys
    from datetime import datetime, timedelta, timezone
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "out")
    target.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    templates = generate("acme-iga-01", "123456789012", "us-east-1", "us-west-2", "maya@acme.example",
                         (now + timedelta(days=30)).isoformat(), (now - timedelta(hours=36)).isoformat())
    for name, template in zip(["primary", "secondary"], templates):
        (target / (name + ".json")).write_text(json.dumps(template, indent=2))
