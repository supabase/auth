#!/bin/bash
set -e

# Add verbose flag handling
VERBOSE=false
while getopts "v" opt; do
  case $opt in
    v) VERBOSE=true ;;
    *) ;;
  esac
done
shift $((OPTIND-1))

# Add logging function
log() {
  if [ "$VERBOSE" = true ]; then
    echo "$@"
  fi
}

# Check if ENVIRONMENT is passed as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 [-v] <dev|prod>"
  exit 1
fi

# Set docker image name
DOCKER_IMAGE=$1
# validate docker image is present
if [ -z "$DOCKER_IMAGE" ]; then
  echo "Usage: $0 <dev|prod> <docker-image>"
  exit 1
fi

REPO_NAME=$2
# validate repo name is present
if [ -z "$REPO_NAME" ]; then
  echo "Usage: $0 <dev|prod> <docker-image> <repo-name>"
  exit 1
fi

# Set environment variable
ENVIRONMENT=$3

# Conditionally validate ENVIRONMENT only if it's provided
if [ -n "$ENVIRONMENT" ]; then
  if [ "$ENVIRONMENT" != "dev" ] && [ "$ENVIRONMENT" != "prod" ]; then
    echo "Invalid environment: $ENVIRONMENT. Use 'dev' or 'prod'."
    exit 1
  fi
  AWS_PROFILE="stork-$ENVIRONMENT"
  PROFILE_FLAG="--profile $AWS_PROFILE"
else
  PROFILE_FLAG=""
fi

AWS_REGION="ap-northeast-1"

VERSION=$(git rev-parse --short=7 HEAD)

REGISTRY_ID=$(aws ecr describe-repositories --repository-names "$REPO_NAME" --query "repositories[0].registryId" --output text $PROFILE_FLAG)
DOCKER_REPO=$REGISTRY_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$REPO_NAME

log 'Tagging ...'
docker tag "$DOCKER_IMAGE" "$DOCKER_REPO:latest"

LOGIN_COMMAND=$(aws ecr get-login-password $PROFILE_FLAG | docker login --username AWS --password-stdin $REGISTRY_ID.dkr.ecr.$AWS_REGION.amazonaws.com)

# Check if login was successful
if [ $? -eq 0 ]; then
  log "Successfully logged in to ECR registry $REGISTRY_ID."
else
  echo "Failed to log in to ECR registry."
  exit 1
fi

log "Pushing ... $DOCKER_REPO:latest ($REPO_NAME:$VERSION)"

if [ "$VERBOSE" = true ]; then
  docker push "$DOCKER_REPO:latest"
else
  docker push "$DOCKER_REPO:latest" --quiet
fi
log "Successfully pushed image to $DOCKER_REPO:latest"
