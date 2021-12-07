#!/bin/bash

VERSION=$(git describe --tags --abbrev=0)

if [ -z "$DOCKER_IMAGE" ]; then
    DOCKER_IMAGE="yutarohayakawa/ipftrace2"
fi

docker build --no-cache -f docker/Dockerfile -t $DOCKER_IMAGE:$VERSION .
docker tag $DOCKER_IMAGE:$VERSION $DOCKER_IMAGE:latest
