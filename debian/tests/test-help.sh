#!/bin/sh

set -e

# Ensure --help works
dhcpig --help >$AUTOPKGTEST_TMP/output

# Ensure --help prints something useful
if ! grep -q "http://github.com/kamorin/DHCPig" $AUTOPKGTEST_TMP/output
then 
    echo "ERROR: dhcpig --help looks wrong (no URL output):"
    cat $AUTOPKGTEST_TMP/output
    exit 1
fi
