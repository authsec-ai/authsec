-- 015_cloud_workload.sql
--
-- The compute that RUNS as a cloud identity: a Lambda function, an ECS task
-- definition, an EC2 instance, a Bedrock agent, a Bedrock AgentCore runtime.
--
-- WHY A NEW TABLE AND NOT iga_agent_instances. iga_agent_instances is the
-- canonical home for a workload once something has decided it belongs to an
-- agent: its agent_id is NOT NULL with a foreign key to iga_agents, so a row
-- cannot exist before that decision is made. Discovery does not make that
-- decision. A scan of an AWS account finds hundreds of Lambda functions, most
-- of which are not agents, and inserting an iga_agents row for each one to
-- satisfy the foreign key would assert agent-ness the scan never established --
-- and would duplicate the agents the Kubernetes connector already writes for
-- the same workloads.
--
-- So this table records the OBSERVATION ("this compute exists and runs as this
-- role") and stops there. Whether a given workload is an agent, and which
-- agent, is a separate judgement a later ticket makes -- at which point this
-- table is the input to it, not a thing to be migrated away. correlated_agent_id
-- is deliberately absent for the same reason: adding it would invite this table
-- to answer a question it cannot.
--
-- WHY IT IS NOT cloud_identity. A workload is not an identity. It HAS one: the
-- role it runs as, which cloud_identity already holds because ticket [1]
-- discovered it independently from IAM. identity_id is that role, and it is
-- nullable because the link is the thing most likely to be missing -- a Lambda
-- with no execution role attached, a task definition naming a role in another
-- account, or an IAM read that was denied while the Lambda read succeeded.
-- A workload with a NULL identity_id is a real finding (compute nobody can
-- attribute), not a broken row.
--
-- WHY runtime_kind IS TEXT. Same argument as cloud_resource.kind: AWS ships new
-- compute services, and an enum would need a migration for each. The values AWS
-- discovery writes today are lambda_function, ecs_task_definition, ec2_instance,
-- bedrock_agent and bedrock_agentcore_runtime; GCP and Azure will add their own
-- without touching this file.
--
-- WHY THE ECS ROLE DISTINCTION IS RECORDED IN attrs, NOT A COLUMN. An ECS task
-- definition names two roles: taskRoleArn, which the application acts as, and
-- executionRoleArn, which ECS itself uses to pull images and write logs.
-- identity_id is always the TASK role -- attributing a container's permissions
-- to the execution role would report the wrong permissions entirely. The
-- execution role is kept in attrs for the reader who needs it, because it is an
-- ECS-only concept and does not belong in a cross-cloud column.
--
-- NO SECRET VALUES. Lambda returns environment variable VALUES with the
-- function, and there is no IAM action that returns the names alone. Only names
-- are recorded here, in attrs; values are discarded at parse time. That is a
-- code obligation (see internal/awsdiscovery/workloads.go) because IAM cannot
-- enforce it, and this table has no column a value could be written to.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction. This file must not open one of its own.

CREATE TABLE IF NOT EXISTS public.cloud_workload (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The role this compute runs as. NULL means unattributed, which is a
    -- finding, not a defect -- see the header. ON DELETE SET NULL rather than
    -- CASCADE: if the role is deleted the workload still exists and still
    -- matters; losing the row would hide compute that just became
    -- unattributable.
    identity_id uuid
        REFERENCES public.cloud_identity(id) ON DELETE SET NULL,

    -- lambda_function | ecs_task_definition | ec2_instance | bedrock_agent |
    -- bedrock_agentcore_runtime. Text, not an enum -- see the header.
    runtime_kind text NOT NULL,

    -- The provider's own identifier, verbatim: a function ARN, a task
    -- definition ARN, an instance id, an agent id. The cross-scan join key.
    native_id text NOT NULL,

    name text NOT NULL DEFAULT '',

    -- The region the workload was found in. Unlike IAM, every service in this
    -- table is regional, and the same name can exist in two regions as two
    -- different workloads.
    region text NOT NULL DEFAULT '',

    -- Provider-specific detail: the ECS execution role, a Lambda's environment
    -- variable NAMES (never values), an EC2 instance profile ARN, a Bedrock
    -- foundation model. Never a secret value.
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Reconciliation, identical in shape to cloud_identity, cloud_secret and
    -- cloud_assume_edge, and driven by the same connector generation.
    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_workload_runtime_kind_chk CHECK (runtime_kind <> ''),
    CONSTRAINT cloud_workload_native_id_chk CHECK (native_id <> ''),
    CONSTRAINT cloud_workload_generation_chk CHECK (last_seen_generation >= 0)
);

-- One row per workload per workspace. native_id is an ARN or an instance id,
-- already unique per account and region, so a re-scan updates rather than
-- duplicating. Scoped by workspace, not connector: re-onboarding an account
-- produces the same connector row, and two workspaces may legitimately watch
-- the same account.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_workload_native
    ON public.cloud_workload (workspace_id, native_id);

-- The scan's own reconciliation query.
CREATE INDEX IF NOT EXISTS idx_cloud_workload_connector_generation
    ON public.cloud_workload (connector_id, last_seen_generation);

-- "What runs as this role" -- the question this table exists to answer, and the
-- join a later classification ticket walks to decide whether a role's compute
-- makes it an agent.
CREATE INDEX IF NOT EXISTS idx_cloud_workload_identity
    ON public.cloud_workload (identity_id)
    WHERE identity_id IS NOT NULL;

-- "Show me every unattributed workload" -- compute nobody can tie to a role.
CREATE INDEX IF NOT EXISTS idx_cloud_workload_unattributed
    ON public.cloud_workload (workspace_id, runtime_kind)
    WHERE identity_id IS NULL;
