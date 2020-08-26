#! /usr/bin/env bash

export BRANCH=$(git symbolic-ref --short HEAD)
export DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export IMAGE_NAME=narrative-traefiker
export COMMIT=$(git rev-parse --short HEAD)
export PR=9001

docker login -u jsfillman -p $TOKEN docker.pkg.github.com
docker build --build-arg BUILD_DATE=$DATE \
             --build-arg COMMIT=$COMMIT \
             --build-arg BRANCH=$BRANCH \
             --build-arg PULL_REQUEST=$PR \
             --label us.kbase.vcs-pull-req=$PR \
             -t $IMAGE_NAME"-test" .
docker tag $IMAGE_NAME"-test" docker.pkg.github.com/jsfillman/$IMAGE_NAME/$IMAGE_NAME"-test"
docker push docker.pkg.github.com/jsfillman/$IMAGE_NAME/$IMAGE_NAME"-test"