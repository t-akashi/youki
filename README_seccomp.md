# Build youki

./scripts/build.sh -o . -r -c youki -f seccomp,oci_seccomp

# Debug seccomp rules

## copy dump file
podman run  --log-level=debug --runtime youki alpine ls /tmp 2>&1 | tee /tmp/alpine.txt
podman cp <container>:/tmp/filter.prog /tmp/filter.prog

## disable it
cat /tmp/filter.prog | ../libseccomp/tools/scmp_bpf_disasm -a x86 2>&1 | tee /tmp/filter.txt

# Unit test
scripts/cargo.sh test -p seccomp --test filter_podman -- --test-threads=1 --no-capture

# Functional Test

## Pre-check

podman create --name sctest --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine true
podman container init sctest
jq '.linux.seccomp' "$(podman inspect --format '{{.OCIConfigPath}}' sctest)"
podman inspect sctest | grep OCIRuntime

### Run the following commands:

(1)
youki % podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine grep Seccomp /proc/self/status
Seccomp:        2
Seccomp_filters:        1

(2)
youki % podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine mkdir /tmp/x
mkdir: can't create directory '/tmp/x': Address not available

youki % podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine chmod 600 /etc/hostname; echo "exit=$?"
exit=159

(3)
youki % podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine sh -c 'ping -6 -c1 ::1; echo "v6=$?"; ping -4 -c1 127.0.0.1; echo "v4=$?"'
PING ::1 (::1): 56 data bytes
64 bytes from ::1: seq=0 ttl=64 time=0.050 ms

--- ::1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.050/0.050/0.050 ms
v6=0
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: can't create raw socket: Address family not supported by protocol
v4=1

(4)
youki % podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine uname -a
Linux 192511330eed 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 Linux
youki % journalctl -k --since -1min | grep -E 'type=1326|SECCOMP'
11月 13 14:34:52 octopus kernel: audit: type=1326 audit(1794548092.803:6314): auid=1000 uid=1000 gid=1000 ses=3 subj=podman pid=2531007 comm="uname" exe="/bin/busybox" sig=0 arch=c000003e syscall=63 compat=0 ip=0x7de90c802e29 code=0x7ffc0000
