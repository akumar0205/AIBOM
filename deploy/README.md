# AIBOM Deployment Assets

This directory contains production-oriented deployment assets for running the `aibom generate` workflow in containerized CI/CD pipelines and Kubernetes clusters.

## Contents

- `Dockerfile`: Production container image for the AIBOM CLI.
- `k8s/aibom-generate.yaml`: Secure Kubernetes `Job` and `CronJob` examples.

## Environment variable contract

The Kubernetes examples use this env var contract:

| Variable | Required | Source | Description |
|---|---|---|---|
| `AIBOM_TARGET_PATH` | Yes | Config/env | Path to the repository or workspace to scan (CLI `target`). |
| `AIBOM_OUTPUT_PATH` | Yes | Config/env | Path where generated AIBOM JSON is written (`--output`). |
| `AIBOM_BUNDLE_PATH` | No | Config/env | Optional bundle output file (`--bundle-out`). |
| `AIBOM_ENV` | Recommended | `ConfigMap` (`aibom-config`) | Logical environment label (e.g. `staging`, `prod`) for audit metadata in surrounding pipelines. |
| `AIBOM_GIT_SHA` | Recommended | `ConfigMap` (`aibom-config`) | Git commit SHA associated with the scanned source. |
| `GITHUB_TOKEN` | Optional | `Secret` (`aibom-secrets`) | Optional token if the surrounding workflow needs GitHub API access. |

> Note: `aibom generate` itself does not require `GITHUB_TOKEN` by default; it is included for common CI/CD integrations.

## Runtime security posture

The provided Job/CronJob apply hardened runtime defaults:

- Runs as non-root user/group `10001`.
- `readOnlyRootFilesystem: true`.
- `allowPrivilegeEscalation: false`.
- All Linux capabilities dropped (`capabilities.drop: ["ALL"]`).
- `seccompProfile.type: RuntimeDefault`.
- `automountServiceAccountToken: false`.
- Explicit CPU and memory requests/limits.

## Build and deploy

### 1) Build and publish the image

```bash
docker build -f deploy/Dockerfile -t ghcr.io/example-org/aibom-cli:1.0.0 .
docker push ghcr.io/example-org/aibom-cli:1.0.0
```

### 2) Create/refresh config and secrets

```bash
kubectl create configmap aibom-config \
  --from-literal=AIBOM_ENV=staging \
  --from-literal=AIBOM_GIT_SHA=$(git rev-parse HEAD) \
  -n aibom --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic aibom-secrets \
  --from-literal=GITHUB_TOKEN="$GITHUB_TOKEN" \
  -n aibom --dry-run=client -o yaml | kubectl apply -f -
```

### 3) Sample end-to-end deployment commands

#### Staging

```bash
IMAGE_TAG=staging-$(git rev-parse --short HEAD)
docker build -f deploy/Dockerfile -t ghcr.io/example-org/aibom-cli:${IMAGE_TAG} . && \
docker push ghcr.io/example-org/aibom-cli:${IMAGE_TAG} && \
sed "s#ghcr.io/example-org/aibom-cli:1.0.0#ghcr.io/example-org/aibom-cli:${IMAGE_TAG}#g" deploy/k8s/aibom-generate.yaml | \
  kubectl apply -n aibom-staging -f - && \
kubectl create job --from=cronjob/aibom-generate-nightly aibom-generate-manual-$(date +%s) -n aibom-staging
```

#### Production

```bash
IMAGE_TAG=1.0.0
docker build -f deploy/Dockerfile -t ghcr.io/example-org/aibom-cli:${IMAGE_TAG} . && \
docker push ghcr.io/example-org/aibom-cli:${IMAGE_TAG} && \
sed "s#ghcr.io/example-org/aibom-cli:1.0.0#ghcr.io/example-org/aibom-cli:${IMAGE_TAG}#g" deploy/k8s/aibom-generate.yaml | \
  kubectl apply -n aibom-prod -f - && \
kubectl create job --from=cronjob/aibom-generate-nightly aibom-generate-release-${IMAGE_TAG}-$(date +%s) -n aibom-prod
```
