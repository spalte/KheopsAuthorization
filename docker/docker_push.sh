#!/bin/bash
echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

mv build/libs/KheopsAuthorization.war docker/KheopsAuthorization.war

docker build ./docker/ -t osirixfoundation/kheops-authorization:$BRANCH

docker push osirixfoundation/kheops-authorization:$BRANCH
