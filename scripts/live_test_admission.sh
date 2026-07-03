#!/usr/bin/env bash
# Live integration test for the PicoSentry K8s admission webhook.
#
# Creates a throw-away kind cluster, deploys the local PicoSentry image as an
# in-cluster TLS webhook, registers a ValidatingWebhookConfiguration, and
# verifies that privileged pods are denied while compliant pods are allowed.
#
# Requirements: kind, kubectl, docker in PATH. Installs nothing system-wide.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="${PICOSENTRY_KIND_CLUSTER:-picosentry-admission-test}"
NAMESPACE="picosentry"
WEBHOOK_SVC="admission-webhook"
SKIP_CREATE="${PICOSENTRY_KIND_SKIP_CREATE:-0}"

# Allow callers to override the image under test (e.g. a released tag). When
# not overridden we build the local Dockerfile so CI always tests the code in
# the current commit.
IMAGE="${PICOSENTRY_IMAGE:-}"
if [[ -z "${IMAGE}" ]]; then
    IMAGE="picosentry:local"
fi

# Ensure tools are available.
command -v kind >/dev/null 2>&1 || { echo "kind not found in PATH"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found in PATH"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker not found in PATH"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl not found in PATH"; exit 1; }

CERT_DIR="$(mktemp -d)"

# When an external step (e.g. helm/kind-action in CI) provisions the cluster,
# we reuse its kubeconfig instead of creating our own.
if [[ "${SKIP_CREATE}" == "1" ]]; then
    : "# use default kubeconfig"
else
    KUBECONFIG="${CERT_DIR}/kubeconfig"
    export KUBECONFIG
fi

dump_logs() {
    echo "--- webhook logs ---"
    kubectl logs -n "${NAMESPACE}" deployment/admission-webhook --tail=100 || true
    echo "--- webhook pod status ---"
    kubectl get pods -n "${NAMESPACE}" || true
}

cleanup() {
    dump_logs || true
    echo "Cleaning up..."
    if [[ "${SKIP_CREATE}" != "1" ]]; then
        kind delete cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}" >/dev/null 2>&1 || true
    fi
    rm -rf "${CERT_DIR}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Cluster
# ---------------------------------------------------------------------------
if [[ "${SKIP_CREATE}" == "1" ]]; then
    echo "Reusing existing kind cluster '${CLUSTER_NAME}'..."
else
    echo "Creating kind cluster '${CLUSTER_NAME}'..."
    cat > "${CERT_DIR}/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 8443
        hostPort: 8443
        listenAddress: 127.0.0.1
EOF
    kind create cluster --name "${CLUSTER_NAME}" --config "${CERT_DIR}/kind-config.yaml" --kubeconfig "${KUBECONFIG}" --wait 2m
fi

# ---------------------------------------------------------------------------
# 2. TLS certificates
# ---------------------------------------------------------------------------
echo "Generating webhook TLS certificates..."
SERVICE_CN="${WEBHOOK_SVC}.${NAMESPACE}.svc"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=picosentry-admission-ca" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
    -keyout "${CERT_DIR}/tls.key" -out "${CERT_DIR}/tls.csr" \
    -subj "/CN=${SERVICE_CN}" -addext "subjectAltName=DNS:${SERVICE_CN}" 2>/dev/null

openssl x509 -req -in "${CERT_DIR}/tls.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial -out "${CERT_DIR}/tls.crt" -days 1 \
    -extfile <(printf "subjectAltName=DNS:%s\n" "${SERVICE_CN}") 2>/dev/null

CA_BUNDLE="$(base64 -w 0 "${CERT_DIR}/ca.crt")"

# ---------------------------------------------------------------------------
# 3. Build (if needed) and load local image into kind
# ---------------------------------------------------------------------------
if [[ "${IMAGE}" == picosentry:local ]]; then
    echo "Building local PicoSentry image..."
    docker build -t "${IMAGE}" "${REPO_ROOT}"
fi

echo "Loading ${IMAGE} into kind..."
if [[ "${SKIP_CREATE}" == "1" ]]; then
    kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
else
    kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}"
fi

# ---------------------------------------------------------------------------
# 4. Deploy webhook
# ---------------------------------------------------------------------------
echo "Deploying admission webhook..."
kubectl create namespace "${NAMESPACE}"
kubectl create secret tls admission-webhook-tls \
    --namespace "${NAMESPACE}" \
    --cert="${CERT_DIR}/tls.crt" \
    --key="${CERT_DIR}/tls.key"

cat > "${CERT_DIR}/webhook.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: admission-webhook
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: admission-webhook
  template:
    metadata:
      labels:
        app: admission-webhook
    spec:
      containers:
        - name: webhook
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - admission
            - --host=0.0.0.0
            - --port=8443
            - --cert-file=/certs/tls.crt
            - --key-file=/certs/tls.key
          volumeMounts:
            - name: certs
              mountPath: /certs
              readOnly: true
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 8443
      volumes:
        - name: certs
          secret:
            secretName: admission-webhook-tls
---
apiVersion: v1
kind: Service
metadata:
  name: ${WEBHOOK_SVC}
  namespace: ${NAMESPACE}
spec:
  selector:
    app: admission-webhook
  ports:
    - port: 443
      targetPort: 8443
EOF
kubectl apply -f "${CERT_DIR}/webhook.yaml"
kubectl wait --namespace "${NAMESPACE}" --for=condition=available --timeout=120s deployment/admission-webhook

# ---------------------------------------------------------------------------
# 5. Register ValidatingWebhookConfiguration
# ---------------------------------------------------------------------------
echo "Registering ValidatingWebhookConfiguration..."
cat > "${CERT_DIR}/vwc.yaml" <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: picosentry-admission
webhooks:
  - name: validate-pods.picosentry.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    clientConfig:
      service:
        name: ${WEBHOOK_SVC}
        namespace: ${NAMESPACE}
        path: /validate
        port: 443
      caBundle: ${CA_BUNDLE}
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["${NAMESPACE}", "kube-system", "kube-public", "kube-node-lease"]
EOF
kubectl apply -f "${CERT_DIR}/vwc.yaml"

# Give the API server a moment to load the webhook.
sleep 5

# ---------------------------------------------------------------------------
# 6. Test: privileged pod must be denied
# ---------------------------------------------------------------------------
echo "Testing privileged pod denial..."
cat > "${CERT_DIR}/bad-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:latest
      securityContext:
        privileged: true
EOF
if kubectl apply -f "${CERT_DIR}/bad-pod.yaml" 2>&1 | tee "${CERT_DIR}/bad-pod.out"; then
    echo "FAIL: privileged pod was admitted"
    kubectl get pod privileged-pod -n default || true
    exit 1
fi
grep -qi "privileged\|denied\|container 'nginx' is privileged" "${CERT_DIR}/bad-pod.out" || {
    echo "FAIL: privileged pod rejection did not contain expected denial reason"
    exit 1
}
echo "PASS: privileged pod was denied"

# ---------------------------------------------------------------------------
# 7. Direct webhook probe from inside the cluster
# ---------------------------------------------------------------------------
echo "Probing webhook directly with a compliant AdmissionReview..."
cat > "${CERT_DIR}/probe.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: probe
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  containers:
    - name: curl
      image: curlimages/curl:latest
      command: ["sh", "-c"]
      args:
        - |
          curl -sk -X POST https://admission-webhook.picosentry.svc:443/validate \\
            -H "Content-Type: application/json" \\
            -d '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"probe-uid","kind":{"group":"","version":"v1","kind":"Pod"},"name":"compliant-pod","namespace":"default","operation":"CREATE","object":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"compliant-pod","namespace":"default"},"spec":{"containers":[{"name":"nginx","image":"nginx:latest","securityContext":{}}]}}}}' \\
            -o /tmp/response.json
          cat /tmp/response.json
EOF
kubectl apply -f "${CERT_DIR}/probe.yaml"
kubectl wait --namespace "${NAMESPACE}" --for=condition=ready --timeout=60s pod/probe || true
kubectl logs -n "${NAMESPACE}" probe || true
kubectl delete pod probe -n "${NAMESPACE}" --ignore-not-found=true || true

# ---------------------------------------------------------------------------
# 8. Test: compliant pod must be allowed
# ---------------------------------------------------------------------------
echo "Testing compliant pod admission..."
cat > "${CERT_DIR}/good-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
  containers:
    - name: nginx
      image: nginx:latest
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65534
        capabilities:
          drop:
            - ALL
EOF
kubectl apply -f "${CERT_DIR}/good-pod.yaml"
kubectl wait --namespace default --for=condition=ready --timeout=120s pod/compliant-pod || true
if kubectl get pod compliant-pod -n default -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True; then
    echo "PASS: compliant pod admitted and ready"
else
    # Ready state depends on image pull; being admitted is the real test.
    if kubectl get pod compliant-pod -n default >/dev/null 2>&1; then
        echo "PASS: compliant pod was admitted ( Ready state depends on image pull )"
    else
        echo "FAIL: compliant pod was not created"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# 8. Test: pod without container securityContext must be denied
# ---------------------------------------------------------------------------
echo "Testing missing container securityContext denial..."
cat > "${CERT_DIR}/no-secctx-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: no-secctx-pod
  namespace: default
spec:
  containers:
    - name: nginx
      image: nginx:latest
EOF
if kubectl apply -f "${CERT_DIR}/no-secctx-pod.yaml" >/dev/null 2>&1; then
    echo "FAIL: pod without container securityContext was admitted"
    kubectl delete pod no-secctx-pod -n default --ignore-not-found=true || true
    exit 1
fi
echo "PASS: pod without container securityContext was denied"

echo ""
echo "All admission controller live-tests passed."
