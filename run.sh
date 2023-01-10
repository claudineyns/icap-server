#!/bin/sh

DOCKER=$(which docker)
PODMAN=$(which podman)

if [ ! "$DOCKER" = "" ]; then
    CONTAINER=$DOCKER
fi

if [ ! "$PODMAN" = "" ]; then
    CONTAINER=$PODMAN
fi

if [ ! "$CONTAINER" = "" ]; then
    $CONTAINER stop icap-server
    mvn package && $CONTAINER build -t icap-server -f Dockerfile.dev . && $CONTAINER run -d --rm --name icap-server -v /tmp:/var/lib/clamav -p1344:1344 icap-server
else
    echo 'Container runtime not found!'
    exit 1
fi
