#!/bin/bash -e
KSU_GIT_VERSION=$(git rev-list --count HEAD)
KSU_VERSION=$(expr 10000 + $KSU_GIT_VERSION + 200)
echo $KSU_VERSION
