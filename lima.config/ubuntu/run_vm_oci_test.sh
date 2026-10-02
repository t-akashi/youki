#!/bin/sh

set -eu

cleanup() {
    local exit_code=$?

    limactl stop $TEST_VM
    limactl delete $TEST_VM
    exit $exit_code
}
trap cleanup EXIT TERM

TEST_VM=youki_oci_test

limactl create -y --name $TEST_VM --mount-none --cpus 2 --memory 4 --disk 20 template:ubuntu-26.04
limactl start $TEST_VM

limactl cp -r lima.config/ubuntu $TEST_VM:/tmp/scripts
limactl shell $TEST_VM sh -x /tmp/scripts/build_youki.sh
limactl shell $TEST_VM sudo sh -x /tmp/scripts/setup_oci_integration_test.sh
limactl shell $TEST_VM sudo -i sh -x /tmp/scripts/run_oci_integration_test.sh

