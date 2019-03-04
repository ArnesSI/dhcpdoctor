#!/bin/bash

# Check if we are on a tag (based on GitLab CI var or git describe)
if [ -z ${CI_COMMIT_TAG+x} ] && ! git describe --exact-match --tags 2>/dev/null; then
    # really not on a tag - append rev info to version
    VER_APPEND=$(git describe --tags | cut -d'-' -f 2- | sed s/-/+/g)
    if [ -z ${VER_APPEND} ]; then exit 1; fi
    bumpversion --no-commit --no-tag --allow-dirty --list --serialize "{major}.{minor}.{patch}.dev${VER_APPEND}" patch
fi
