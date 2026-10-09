#!/usr/bin/env bash
# Mint the KUBECONFIG_B64 secret for .github/workflows/deploy.yml.
#
# Run this on a machine with cluster-admin, AFTER:
#   kubectl apply -f deploy/github-deployer-rbac.yaml
#
# It prints ONE base64 line. Pipe it straight into `gh secret set` -- do not
# paste it into a chat, a file, or a commit:
#
#   ./scripts/make-deployer-kubeconfig.sh | gh secret set KUBECONFIG_B64 \
#       --repo authsec-ai/authsec
#
# The UI repo's deploy workflow needs the same secret:
#
#   ./scripts/make-deployer-kubeconfig.sh | gh secret set KUBECONFIG_B64 \
#       --repo authsec-ai/Authsec-ui
#
# WHY NOT /etc/rancher/k3s/k3s.yaml: that file is cluster-admin and its server
# is 127.0.0.1, so it is both over-privileged for CI and unusable from outside
# the node. This produces a credential scoped to replacing an image on one
# Deployment, pointed at the API's reachable address.
set -euo pipefail

SERVER="${SERVER:-https://37.27.104.185:6443}"
NAMESPACE="${NAMESPACE:-authsec-prod}"
SA="${SA:-github-deployer}"
SECRET="${SECRET:-github-deployer-token}"

# Point this at a wrapper if kubectl is not on PATH, e.g.
#   KUBECTL=~/.claude/authsec-k3s/kubectl ./scripts/make-deployer-kubeconfig.sh
#
# Use this rather than adding the wrapper's directory to PATH. That directory
# can hold a script named `ssh`, and putting it on PATH makes the wrapper
# resolve `ssh` to ITSELF -- it recurses, appending its own arguments each
# time, and hangs having built a multi-megabyte command line.
KUBECTL="${KUBECTL:-kubectl}"

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
command -v "$KUBECTL" >/dev/null || { echo "missing: $KUBECTL" >&2; exit 1; }
need base64

# Read the Secret as YAML and pick the fields out locally.
#
# NOT jsonpath: this may be driven through a wrapper that shells out over ssh
# as `kubectl $*`, which loses the quoting around '{.data.token}' and lets the
# REMOTE shell brace-expand it. That fails confusingly or hangs. YAML has no
# characters a shell wants to touch.
secret_yaml="$("$KUBECTL" get secret "$SECRET" -n "$NAMESPACE" -o yaml)"
field() { printf '%s\n' "$secret_yaml" | awk -v k="$1:" '$1 == k { print $2; exit }'; }

token="$(field token | base64 -d)"
ca="$(field ca.crt)"

if [ -z "$token" ] || [ -z "$ca" ]; then
    echo "token or CA empty -- has deploy/github-deployer-rbac.yaml been applied?" >&2
    exit 1
fi

# Fail loudly rather than emitting a kubeconfig that cannot deploy. A silently
# under-privileged credential turns into a red workflow at the worst moment.
if ! "$KUBECTL" auth can-i patch deployments \
        -n "$NAMESPACE" \
        --as="system:serviceaccount:${NAMESPACE}:${SA}" >/dev/null; then
    echo "$SA cannot patch deployments in $NAMESPACE -- check the RoleBinding" >&2
    exit 1
fi

cat <<YAML | base64 | tr -d '\n'
apiVersion: v1
kind: Config
clusters:
  - name: authsec
    cluster:
      server: ${SERVER}
      certificate-authority-data: ${ca}
contexts:
  - name: deployer
    context:
      cluster: authsec
      namespace: ${NAMESPACE}
      user: ${SA}
current-context: deployer
users:
  - name: ${SA}
    user:
      token: ${token}
YAML
echo
