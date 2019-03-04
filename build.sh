#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

set -e "${VERBOSE:+-x}"

ROOT_PATH=$(rpm --eval %_topdir)
RPMSRC_PATH=$(rpm --eval %_sourcedir)
BUILD_PATH=$(rpm --eval %_builddir)
SPECS_PATH=$(rpm --eval %_specdir)

# Create rpmbuild dirs
#mkdir -p $ROOT_PATH/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Clean build dirs (do not clean $ROOT_PATH/*RPMS)
#rm -rf $ROOT_PATH/{BUILD,BUILDROOT,SOURCES,SPECS}/*

# Python: generate tarball
poetry build --format=sdist

# Python: Get version number
VERSION=$(grep '__version__ = ' dhcpdoctor/dhcpdoctor.py | sed -r s,"^.*=\s*[\'\"](.+)[\'\"].*","\1",)

# Find source spec file
SPEC_SRC=`ls *.spec`
SPEC_FILE="$SPECS_PATH/$SPEC_SRC"

# Copy spec file and write version info
sed "s/_VERSION_/${VERSION}/" $SPEC_SRC > $SPEC_FILE

# Guess the pkg name
PKG_NAME=$(rpmspec --srpm -q --queryformat='%{name}' $SPEC_FILE)

# Install build dependencies
yum-builddep -y ${SPEC_FILE} || exit 1

# List and download sources
spectool ${SPEC_FILE}
spectool -g -R ${SPEC_FILE} || exit 1

# Copy extra files (eval by rpm to ensure macros are expanded)
EVALSPEC=$(rpmspec -P $SPEC_FILE)
for i in $(echo "$EVALSPEC" | grep '^Source.*:' | awk '{print $2}') \
         $(echo "$EVALSPEC" | grep '^Patch.*:' | awk '{print $2}'); do
    for j in $i $(basename $i); do
        [ -f $j ] && cp -f $j $RPMSRC_PATH && break
    done
done

# Build RPM package (but dont build debuginfo package)
rpmbuild -ba $SPEC_FILE --define "debug_package %{nil}" --define "_rpmdir $(pwd)/rpms" --define "_srcrpmdir $(pwd)/srpms"
