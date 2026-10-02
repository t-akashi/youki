#!/bin/sh

set -eu

if [ $(id -u) -ne 0 ]; then
    echo "You must run this script as root." >&2
    exit 1
fi

cd /root/go/src/github.com/containerd/containerd

export RUNC_FLAVOR=crun
make TEST_RUNTIME=io.containerd.runc.v2 TESTFLAGS="-timeout 120m" integration | tee /tmp/oci_test.log

PASS=$(grep "PASS: " /tmp/oci_test.log | wc -l)
FAIL=$(grep "FAIL: " /tmp/oci_test.log | wc -l)
SKIP=$(grep "SKIP: " /tmp/oci_test.log | wc -l)
TOTAL=$((PASS + FAIL + SKIP))
echo
echo "TOTAL: $TOTAL PASS: $PASS FAIL: $FAIL SKIP: $SKIP"

if [ $TOTAL -eq $PASS ]; then
    exit 0
else
    exit 1
fi
