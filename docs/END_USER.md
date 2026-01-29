# Sim-AWS end-user guide

## Prerequisites

- A Morph API key (`MORPH_API_KEY`).
- Docker (for the connector).
- AWS CLI/SDK config: set dummy credentials if you don’t already have a profile (LocalStack-style simulators still require signing):
  - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_SESSION_TOKEN`)

## Install the CLI plugin (development branch)

Until the `morph-python-sdk` PR is merged/released, install from the PR branch:

```bash
pip install "git+https://github.com/morph-labs/morph-python-sdk.git@<BRANCH_NAME>"
```

## Create an environment

```bash
export MORPH_API_KEY="..."
export SIM_AWS_BASE_URL="https://sim-aws.svc.cloud.morph.so"

morphcloud env aws-sim create --region us-east-1 --service s3 --service sqs --service lambda
morphcloud env aws-sim list
```

Copy the returned `env_id` (looks like `awsenv_...`).

## Connect (get bundle + run connector)

```bash
morphcloud env aws-sim connect <env_id> --output ./aws-sim-connect-bundle.json
```

The connect bundle is sensitive (contains a WireGuard private key). Keep it safe (the CLI attempts to chmod it to `0600`).

Run the connector (the CLI prints a `docker run ...` command; example below):

```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e MORPH_API_KEY \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_REGION -e AWS_DEFAULT_REGION -e AWS_PROFILE \
  -v "$PWD/aws-sim-connect-bundle.json:/bundle.json:ro" \
  ghcr.io/morph-labs/sim-aws-connector:latest \
  --bundle /bundle.json
```

Inside the container, AWS CLI should work **with default endpoints** (no `--endpoint-url`):

```bash
aws s3 ls
aws sqs list-queues
aws lambda list-functions
```

## Snapshot + restore

```bash
morphcloud env aws-sim snapshot <env_id>
morphcloud env aws-sim restore <env_id> <snapshot_id>
```

