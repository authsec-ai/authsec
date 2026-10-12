package iacpr

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// CloudFormation dedicated identity (§11 isolation; review P1-12 (e)): the
// split is rendered for CloudFormation sources too, from the plan's archived
// documents, never by copying the source's text:
//
//   - a new AWS::IAM::Role with the approved trust policy, the approved
//     managed policies by ARN (ManagedPolicyArns), the approved inline
//     policies (Policies) and the approved boundary;
//   - the binding moves: ECS, the task definition's TaskRoleArn (a new
//     revision; every subject service moves to it); Lambda, the function's
//     Role plus a new AWS::Lambda::Version that its aliases move to; EC2 Auto
//     Scaling, a new AWS::IAM::InstanceProfile in the launch template and a
//     rolling-update policy on the group;
//   - split_revert moves the binding back and removes what the split added
//     (unless the new role has other consumers now, KeepNewRole).
//
// Forms that cannot be changed mechanically fall back to export at compile
// time with their reason, exactly as for Terraform (§8.11). A standalone
// EC2 instance subject is not located in source (no stable declaration
// shape) and falls back with iac_form_unsupported -- the same DECISION as
// the Terraform renderer.

type cfnSource struct {
	t   *cfnTemplate
	src string
}

func loadCFN(req Request) ([]cfnSource, error) {
	var ts []cfnSource
	for _, p := range sortedKeys(req.Files) {
		ext := strings.ToLower(path.Ext(p))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" && ext != ".template" {
			continue
		}
		if !isCFNTemplate(req.Files[p]) {
			continue
		}
		t, err := parseCFN(p, req.Files[p])
		if err != nil {
			return nil, fallback(ReasonFormUnsupported, "%v", err)
		}
		if t.Transform {
			return nil, fallback(ReasonGeneratedSource, "%s uses Transform (SAM or a macro)", p)
		}
		ts = append(ts, cfnSource{t, req.Files[p]})
	}
	if len(ts) == 0 {
		return nil, fallback(ReasonRoleNotFound, "no CloudFormation templates in %s", req.Source.Directory)
	}
	return ts, nil
}

// locateCFNRole finds the AWS::IAM::Role of a role name (role_match rule or
// literal RoleName), exactly once.
func locateCFNRole(req Request, ts []cfnSource, name string) (*cfnTemplate, cfnResource, error) {
	rule := req.Source.RoleMatch.resourceFor(name)
	type hit struct {
		t *cfnTemplate
		r cfnResource
	}
	var hits []hit
	var computed []string
	for _, x := range ts {
		for _, r := range x.t.resources() {
			if r.Type != "AWS::IAM::Role" {
				continue
			}
			if rule != "" {
				if r.LogicalID == rule {
					hits = append(hits, hit{x.t, r})
				}
				continue
			}
			rn := mapGet(r.Props, "RoleName")
			if v, ok := cfnScalar(rn); ok && v == name {
				hits = append(hits, hit{x.t, r})
			} else if rn != nil && !ok {
				computed = append(computed, x.t.Path+": "+r.LogicalID)
			}
		}
	}
	switch {
	case len(hits) > 1:
		var ids []string
		for _, h := range hits {
			ids = append(ids, h.t.Path+": "+h.r.LogicalID)
		}
		return nil, cfnResource{}, fallback(ReasonRoleAmbiguous, "role %s is declared more than once: %s", name, strings.Join(ids, ", "))
	case len(hits) == 0 && rule != "":
		return nil, cfnResource{}, fallback(ReasonRoleNotFound, "role_match names %s, which is not an AWS::IAM::Role in %s", rule, req.Source.Directory)
	case len(hits) == 0 && len(computed) > 0:
		return nil, cfnResource{}, fallback(ReasonFormUnsupported, "role names are computed in %s", strings.Join(computed, ", "))
	case len(hits) == 0:
		return nil, cfnResource{}, fallback(ReasonRoleNotFound, "no AWS::IAM::Role named %s in %s", name, req.Source.Directory)
	}
	return hits[0].t, hits[0].r, nil
}

func cfnGetAttNode(logicalID, attr string, jsonForm bool) *yaml.Node {
	if jsonForm {
		return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{strNode("Fn::GetAtt"),
			{Kind: yaml.SequenceNode, Content: []*yaml.Node{strNode(logicalID), strNode(attr)}}}}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!GetAtt", Value: logicalID + "." + attr}
}

// cfnRefersTo: the node names the resource logicalID (Ref / GetAtt) or the
// role's ARN / name literally.
func cfnRefersTo(n *yaml.Node, logicalID, arn, name string) bool {
	if id, ok := cfnRefTarget(n); ok {
		return id == logicalID
	}
	v, ok := cfnScalar(n)
	return ok && (v == arn || v == name)
}

func (t *cfnTemplate) resource(logicalID string) (cfnResource, bool) {
	for _, r := range t.resources() {
		if r.LogicalID == logicalID {
			return r, true
		}
	}
	return cfnResource{}, false
}

func (t *cfnTemplate) uniqueID(base string) string {
	id := base
	for i := 2; ; i++ {
		if _, ok := t.resource(id); !ok {
			return id
		}
		id = fmt.Sprintf("%s%d", base, i)
	}
}

func cfnDocHash(n *yaml.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	v, err := cfnLiteral(n)
	if err != nil {
		return "", false
	}
	raw, err := jsonMarshalString(v)
	if err != nil {
		return "", false
	}
	h, err := igagov.DocumentHash(raw)
	return h, err == nil
}

func addResource(t *cfnTemplate, id, typ string, props *yaml.Node) *yaml.Node {
	res := &yaml.Node{Kind: yaml.MappingNode}
	mapSet(res, "Type", strNode(typ))
	mapSet(res, "Properties", props)
	mapSet(t.Resources, id, res)
	return res
}

func renderCFNSplit(req Request, ts []cfnSource) (*Change, error) {
	d := req.Plan.Diff.Split
	if d == nil {
		return nil, fmt.Errorf("iacpr: split plan without split detail")
	}
	pf := readPlan(req.Plan, req.DeploymentID)
	srcName, newName := roleNameOf(d.SourceRoleARN), roleNameOf(d.NewRoleARN)
	t, src, err := locateCFNRole(req, ts, srcName)
	if err != nil {
		return nil, err
	}
	if src.Props == nil {
		return nil, fallback(ReasonFormUnsupported, "%s has no Properties", src.LogicalID)
	}
	var newRes *cfnResource
	for _, x := range ts {
		for _, r := range x.t.resources() {
			if r.Type == "AWS::IAM::Role" {
				if v, ok := cfnScalar(mapGet(r.Props, "RoleName")); ok && v == newName {
					rr := r
					if x.t != t {
						return nil, fallback(ReasonFormUnsupported, "role %s is declared in %s, not beside %s", newName, x.t.Path, src.LogicalID)
					}
					newRes = &rr
				}
			}
		}
	}
	var sum []string
	if req.Plan.Kind == igagov.PlanSplit {
		if newRes != nil {
			return nil, fallback(ReasonFormUnsupported, "%s already declares role %s", newRes.LogicalID, newName)
		}
		if pf.createRole == nil {
			return nil, fmt.Errorf("iacpr: split plan without CreateRole")
		}
		newID := t.uniqueID(cfnLogicalID(newName))
		props, err := cfnNewRoleProps(req, t, src, pf, newName)
		if err != nil {
			return nil, err
		}
		addResource(t, newID, "AWS::IAM::Role", props)
		sum = append(sum, fmt.Sprintf("add %s (role %s) with %d managed policies by ARN and the approved inline policies, trust policy and boundary",
			newID, newName, len(pf.attach)))
		s, err := cfnMoveBinding(t, d, src.LogicalID, d.SourceRoleARN, srcName, newID, newName, true)
		if err != nil {
			return nil, err
		}
		sum = append(sum, s...)
		return cfnResult(req, t, src.LogicalID+" -> "+newID, sum)
	}
	// split_revert.
	if newRes == nil {
		return nil, fallback(ReasonRoleNotFound, "the dedicated role %s is not declared in %s", newName, req.Source.Directory)
	}
	s, err := cfnMoveBinding(t, d, newRes.LogicalID, d.NewRoleARN, newName, src.LogicalID, srcName, false)
	if err != nil {
		return nil, err
	}
	sum = append(sum, s...)
	if !req.KeepNewRole {
		mapDelete(t.Resources, newRes.LogicalID)
		for _, r := range t.resources() {
			switch r.Type {
			case "AWS::IAM::InstanceProfile", "AWS::IAM::Policy":
				if roles := mapGet(r.Props, "Roles"); roles != nil && roles.Kind == yaml.SequenceNode && len(roles.Content) == 1 &&
					cfnRefersTo(roles.Content[0], newRes.LogicalID, d.NewRoleARN, newName) {
					mapDelete(t.Resources, r.LogicalID)
				}
			}
		}
		sum = append(sum, "remove "+newRes.LogicalID+" and the resources added for it")
	} else {
		sum = append(sum, "keep "+newRes.LogicalID+": other workloads run as it now")
	}
	return cfnResult(req, t, newRes.LogicalID+" -> "+src.LogicalID, sum)
}

func cfnResult(req Request, t *cfnTemplate, loc string, sum []string) (*Change, error) {
	out, err := t.render()
	if err != nil {
		return nil, err
	}
	ch := &Change{Format: FormatCloudFormation, Location: t.Path + ": " + loc, Files: []FileChange{}, Summary: sum}
	if out != req.Files[t.Path] {
		ch.Files = append(ch.Files, FileChange{Path: t.Path, Before: req.Files[t.Path], After: out})
	}
	return ch, nil
}

// cfnNewRoleProps builds the new role's Properties from the approved plan,
// checking that the source role still declares what was approved.
func cfnNewRoleProps(req Request, t *cfnTemplate, src cfnResource, pf planFacts, newName string) (*yaml.Node, error) {
	trustDoc, err := req.archived(pf.createRole.TrustPolicyHash, "the trust policy")
	if err != nil {
		return nil, err
	}
	if h, ok := cfnDocHash(mapGet(src.Props, "AssumeRolePolicyDocument")); ok && h != pf.createRole.TrustPolicyHash {
		return nil, fallback(ReasonSourceDiffers, "the trust policy of %s in the source differs from the approved one (%s)",
			src.LogicalID, pf.createRole.TrustPolicyHash)
	}
	pols := map[string]string{} // ManagedPolicy logical id -> ARN
	for _, r := range t.resources() {
		if r.Type != "AWS::IAM::ManagedPolicy" {
			continue
		}
		n, ok := cfnScalar(mapGet(r.Props, "ManagedPolicyName"))
		if !ok {
			continue
		}
		p := "/"
		if pn := mapGet(r.Props, "Path"); pn != nil {
			if p, ok = cfnScalar(pn); !ok {
				continue
			}
		}
		pols[r.LogicalID] = "arn:" + req.Role.partition() + ":iam::" + req.Role.AccountID + ":policy" + p + n
	}
	var boundary *yaml.Node
	pb := mapGet(src.Props, "PermissionsBoundary")
	switch {
	case pf.newBoundary == "" && pb != nil:
		return nil, fallback(ReasonSourceDiffers, "%s sets a PermissionsBoundary; the approved role has none", src.LogicalID)
	case pf.newBoundary != "" && pb == nil:
		return nil, fallback(ReasonSourceDiffers, "%s sets no PermissionsBoundary; the approved role has %s", src.LogicalID, pf.newBoundary)
	case pb != nil:
		got, resolved := cfnScalar(pb)
		if id, ok := cfnRefTarget(pb); ok {
			got, resolved = pols[id], pols[id] != ""
		}
		if resolved && got != pf.newBoundary {
			return nil, fallback(ReasonSourceDiffers, "%s.PermissionsBoundary is %s in the source; the approved boundary is %s",
				src.LogicalID, got, pf.newBoundary)
		}
		if resolved {
			boundary = pb // the same policy, written as the source writes it
		} else {
			boundary = strNode(pf.newBoundary)
		}
	}
	// Inline policies: the source's (Policies, and AWS::IAM::Policy naming only
	// the source role) must be exactly the approved ones.
	approved := map[string]string{}
	for _, op := range req.Plan.Ops {
		if op.Op == igagov.OpPutRolePolicy {
			approved[op.InlineName] = op.DocumentHash
		}
	}
	srcInline := map[string]*yaml.Node{}
	if ps := mapGet(src.Props, "Policies"); ps != nil {
		if ps.Kind != yaml.SequenceNode {
			return nil, fallback(ReasonFormUnsupported, "%s.Policies is computed", src.LogicalID)
		}
		for _, p := range ps.Content {
			nm, ok := cfnScalar(mapGet(p, "PolicyName"))
			if !ok {
				return nil, fallback(ReasonFormUnsupported, "an inline policy of %s has a computed name", src.LogicalID)
			}
			srcInline[nm] = mapGet(p, "PolicyDocument")
		}
	}
	for _, r := range t.resources() {
		if r.Type != "AWS::IAM::Policy" {
			continue
		}
		roles := mapGet(r.Props, "Roles")
		if roles == nil || roles.Kind != yaml.SequenceNode {
			continue
		}
		for _, rn := range roles.Content {
			if cfnRefersTo(rn, src.LogicalID, req.Role.ARN, roleNameOf(req.Role.ARN)) {
				nm, ok := cfnScalar(mapGet(r.Props, "PolicyName"))
				if !ok {
					return nil, fallback(ReasonFormUnsupported, "%s has a computed PolicyName", r.LogicalID)
				}
				srcInline[nm] = mapGet(r.Props, "PolicyDocument")
			}
		}
	}
	for nm := range srcInline {
		if _, ok := approved[nm]; !ok {
			return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s is in the source but not in the approved role", nm, src.LogicalID)
		}
	}
	names := make([]string, 0, len(approved))
	for nm := range approved {
		names = append(names, nm)
	}
	sort.Strings(names)
	inline := &yaml.Node{Kind: yaml.SequenceNode}
	for _, nm := range names {
		cur, ok := srcInline[nm]
		if !ok {
			return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s is not declared in %s", nm, src.LogicalID, req.Source.Directory)
		}
		if h, ok := cfnDocHash(cur); ok && h != approved[nm] {
			return nil, fallback(ReasonSourceDiffers, "inline policy %s of %s in the source differs from the approved one", nm, src.LogicalID)
		}
		doc, err := req.archived(approved[nm], "inline policy "+nm)
		if err != nil {
			return nil, err
		}
		dn, err := cfnDocumentNode(doc)
		if err != nil {
			return nil, err
		}
		p := &yaml.Node{Kind: yaml.MappingNode}
		mapSet(p, "PolicyName", strNode(nm))
		mapSet(p, "PolicyDocument", dn)
		inline.Content = append(inline.Content, p)
	}
	tn, err := cfnDocumentNode(trustDoc)
	if err != nil {
		return nil, err
	}
	props := &yaml.Node{Kind: yaml.MappingNode}
	mapSet(props, "RoleName", strNode(newName))
	mapSet(props, "Path", strNode(pf.createRole.Path))
	mapSet(props, "AssumeRolePolicyDocument", tn)
	if len(pf.attach) > 0 {
		m := &yaml.Node{Kind: yaml.SequenceNode}
		for _, a := range pf.attach {
			m.Content = append(m.Content, strNode(a))
		}
		mapSet(props, "ManagedPolicyArns", m)
	}
	if len(inline.Content) > 0 {
		mapSet(props, "Policies", inline)
	}
	if boundary != nil {
		mapSet(props, "PermissionsBoundary", boundary)
	}
	if len(pf.createRole.Tags) > 0 {
		keys := make([]string, 0, len(pf.createRole.Tags))
		for k := range pf.createRole.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		tags := &yaml.Node{Kind: yaml.SequenceNode}
		for _, k := range keys {
			kv := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(kv, "Key", strNode(k))
			mapSet(kv, "Value", strNode(pf.createRole.Tags[k]))
			tags.Content = append(tags.Content, kv)
		}
		mapSet(props, "Tags", tags)
	}
	return props, nil
}

// cfnMoveBinding re-points every subject from role `fromID` to role `toID`
// (logical ids in t). split: true for the split (a new instance profile is
// added), false for the revert (the source role's profile is used again).
func cfnMoveBinding(t *cfnTemplate, d *igagov.SplitDetail, fromID, fromARN, fromName, toID, toName string, split bool) ([]string, error) {
	var sum []string
	scalarProp := func(r cfnResource, k string) string {
		v, _ := cfnScalar(mapGet(r.Props, k))
		return v
	}
	refs := func(n *yaml.Node, id string) bool {
		got, ok := cfnRefTarget(n)
		return ok && got == id
	}
	last := func(a string) string { return a[strings.LastIndexAny(a, "/:")+1:] }
	switch d.SubjectKind {
	case igagov.SubjectECSService:
		subjects := map[string]bool{}
		for _, a := range d.Subjects() {
			subjects[last(a)] = true
		}
		tds := map[string]cfnResource{}
		var order []string
		for _, name := range sortedSet(subjects) {
			var svc *cfnResource
			for _, r := range t.resources() {
				if r.Type == "AWS::ECS::Service" && scalarProp(r, "ServiceName") == name {
					rr := r
					svc = &rr
				}
			}
			if svc == nil {
				return nil, fallback(ReasonRoleNotFound, "ECS service %s is not declared in %s", name, t.Path)
			}
			id, ok := cfnRefTarget(mapGet(svc.Props, "TaskDefinition"))
			td, found := t.resource(id)
			if !ok || !found || td.Type != "AWS::ECS::TaskDefinition" {
				return nil, fallback(ReasonFormUnsupported, "%s.TaskDefinition is not a task definition declared in the template", svc.LogicalID)
			}
			if _, seen := tds[id]; !seen {
				order = append(order, id)
			}
			tds[id] = td
		}
		for _, r := range t.resources() {
			if r.Type != "AWS::ECS::Service" || subjects[scalarProp(r, "ServiceName")] {
				continue
			}
			if id, ok := cfnRefTarget(mapGet(r.Props, "TaskDefinition")); ok {
				if _, shared := tds[id]; shared {
					return nil, fallback(ReasonFormUnsupported, "%s is also used by %s, which is not a subject of this change", id, r.LogicalID)
				}
			}
		}
		for _, id := range order {
			td := tds[id]
			ra := mapGet(td.Props, "TaskRoleArn")
			if ra == nil || !cfnRefersTo(ra, fromID, fromARN, fromName) {
				return nil, fallback(ReasonFormUnsupported, "%s.TaskRoleArn does not name %s", id, fromName)
			}
			mapSet(td.Props, "TaskRoleArn", cfnGetAttNode(toID, "Arn", t.JSON))
			sum = append(sum, "set "+id+".TaskRoleArn to "+toName+" (a new task-definition revision; services "+
				strings.Join(sortedSet(subjects), ", ")+" move to it)")
		}
	case igagov.SubjectLambdaFunction:
		name := last(d.SubjectARN)
		var fn *cfnResource
		for _, r := range t.resources() {
			if r.Type == "AWS::Lambda::Function" && scalarProp(r, "FunctionName") == name {
				rr := r
				fn = &rr
			}
		}
		if fn == nil {
			return nil, fallback(ReasonRoleNotFound, "Lambda function %s is not declared in %s", name, t.Path)
		}
		ra := mapGet(fn.Props, "Role")
		if ra == nil || !cfnRefersTo(ra, fromID, fromARN, fromName) {
			return nil, fallback(ReasonFormUnsupported, "%s.Role does not name %s", fn.LogicalID, fromName)
		}
		mapSet(fn.Props, "Role", cfnGetAttNode(toID, "Arn", t.JSON))
		// A published version's configuration is immutable: a new
		// AWS::Lambda::Version is published and every alias moves to it.
		var aliases []cfnResource
		for _, r := range t.resources() {
			if r.Type == "AWS::Lambda::Alias" && refs(mapGet(r.Props, "FunctionName"), fn.LogicalID) {
				aliases = append(aliases, r)
			}
		}
		if len(aliases) > 0 {
			verID := t.uniqueID(fn.LogicalID + "Version" + cfnLogicalID(toName))
			vp := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(vp, "FunctionName", cfnRefNode(fn.LogicalID, t.JSON))
			mapSet(vp, "Description", strNode("published by AuthSec with role "+toName))
			for _, al := range aliases {
				fv := mapGet(al.Props, "FunctionVersion")
				if v, ok := cfnScalar(fv); ok && v == "$LATEST" {
					continue
				}
				id, ok := cfnRefTarget(fv)
				ver, found := t.resource(id)
				if !ok || !found || ver.Type != "AWS::Lambda::Version" {
					return nil, fallback(ReasonFormUnsupported, "%s pins a version; it would not move to the new version", al.LogicalID)
				}
				mapSet(al.Props, "FunctionVersion", cfnGetAttNode(verID, "Version", t.JSON))
			}
			addResource(t, verID, "AWS::Lambda::Version", vp)
			sum = append(sum, "publish "+verID+" and move the aliases of "+fn.LogicalID+" to it")
		}
		sum = append(sum, "set "+fn.LogicalID+".Role to "+toName)
	case igagov.SubjectEC2ASG:
		name := last(d.SubjectARN)
		var asg *cfnResource
		for _, r := range t.resources() {
			if r.Type == "AWS::AutoScaling::AutoScalingGroup" && scalarProp(r, "AutoScalingGroupName") == name {
				rr := r
				asg = &rr
			}
		}
		if asg == nil {
			return nil, fallback(ReasonRoleNotFound, "Auto Scaling group %s is not declared in %s", name, t.Path)
		}
		ltSpec := mapGet(asg.Props, "LaunchTemplate")
		ltID, ok := cfnRefTarget(mapGet(ltSpec, "LaunchTemplateId"))
		lt, found := t.resource(ltID)
		if !ok || !found || lt.Type != "AWS::EC2::LaunchTemplate" {
			return nil, fallback(ReasonFormUnsupported, "%s does not use a launch template declared in the template", asg.LogicalID)
		}
		if vid, ok := cfnRefTarget(mapGet(ltSpec, "Version")); !ok || vid != ltID {
			return nil, fallback(ReasonFormUnsupported, "%s pins a launch template version", asg.LogicalID)
		}
		for _, r := range t.resources() {
			if r.Type == "AWS::AutoScaling::AutoScalingGroup" && r.LogicalID != asg.LogicalID {
				if id, ok := cfnRefTarget(mapGet(mapGet(r.Props, "LaunchTemplate"), "LaunchTemplateId")); ok && id == ltID {
					return nil, fallback(ReasonFormUnsupported, "%s is also used by %s", ltID, r.LogicalID)
				}
			}
		}
		ipSpec := mapGet(mapGet(lt.Props, "LaunchTemplateData"), "IamInstanceProfile")
		key, profID := "", ""
		for _, k := range []string{"Arn", "Name"} {
			if id, ok := cfnRefTarget(mapGet(ipSpec, k)); ok {
				key, profID = k, id
			}
		}
		prof, found := t.resource(profID)
		if key == "" || !found || prof.Type != "AWS::IAM::InstanceProfile" {
			return nil, fallback(ReasonFormUnsupported, "%s's instance profile is not declared in the template", ltID)
		}
		profileOf := func(roleID, arn, nm string) (string, bool) {
			for _, r := range t.resources() {
				if r.Type != "AWS::IAM::InstanceProfile" {
					continue
				}
				if roles := mapGet(r.Props, "Roles"); roles != nil && roles.Kind == yaml.SequenceNode && len(roles.Content) == 1 &&
					cfnRefersTo(roles.Content[0], roleID, arn, nm) {
					return r.LogicalID, true
				}
			}
			return "", false
		}
		var target string
		if split {
			if roles := mapGet(prof.Props, "Roles"); roles == nil || roles.Kind != yaml.SequenceNode || len(roles.Content) != 1 ||
				!cfnRefersTo(roles.Content[0], fromID, fromARN, fromName) {
				return nil, fallback(ReasonFormUnsupported, "%s does not hold %s", profID, fromName)
			}
			target = t.uniqueID(cfnLogicalID(toName) + "Profile")
			pp := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(pp, "InstanceProfileName", strNode(toName))
			mapSet(pp, "Roles", &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{cfnRefNode(toID, t.JSON)}})
			addResource(t, target, "AWS::IAM::InstanceProfile", pp)
		} else {
			var ok bool
			if target, ok = profileOf(toID, d.SourceRoleARN, toName); !ok {
				return nil, fallback(ReasonFormUnsupported, "no instance profile of %s is declared in the template", toName)
			}
		}
		if key == "Arn" {
			mapSet(ipSpec, "Arn", cfnGetAttNode(target, "Arn", t.JSON))
		} else {
			mapSet(ipSpec, "Name", cfnRefNode(target, t.JSON))
		}
		if mapGet(asg.Node, "UpdatePolicy") == nil {
			up := &yaml.Node{Kind: yaml.MappingNode}
			ru := &yaml.Node{Kind: yaml.MappingNode}
			mapSet(ru, "MaxBatchSize", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
			mapSet(up, "AutoScalingRollingUpdate", ru)
			mapSet(asg.Node, "UpdatePolicy", up)
		}
		sum = append(sum, "move "+ltID+" to the instance profile "+target+" of "+toName+" and roll "+asg.LogicalID+"'s instances")
	default:
		return nil, fallback(ReasonFormUnsupported, "a %s subject cannot be located in source by its id", d.SubjectKind)
	}
	return sum, nil
}

func jsonMarshalString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
