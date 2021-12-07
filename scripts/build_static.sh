#!/bin/bash

# Run this in project top

ROOT=$(pwd)
VERSION=$(git describe --tags --abbrev=0)

if [ -z "$DOCKER_IMAGE" ]; then
    DOCKER_IMAGE="ghcr.io/yutarohayakawa/ipftrace2-builder:$VERSION"
fi

if [ -z "$CONTAINER_NAME" ]; then
    CONTAINER_NAME="ipftrace2-builder"
fi

docker run --rm --name $CONTAINER_NAME -v $ROOT:/mnt $DOCKER_IMAGE /bin/sh -c "cd /mnt/src && make"
