#!/bin/sh
# What tests/redact.sh must do, by example: a failure prints enough to work
# with and no address anyone could be identified by.
set -u

. "$(dirname "$0")/redact.sh"

fail=0

# check <what> <line> <expected>
check() {
	_got=$(printf '%s\n' "$2" | redact)
	if [ "$_got" != "$3" ]; then
		echo "$1"
		echo "  in       $2"
		echo "  wanted   $3"
		echo "  got      $_got"
		fail=1
	fi
}

check "a global v6 endpoint keeps its port and loses its address" \
	"told the host rendezvous at [2a01:e0a:aa7:4940:be24:11ff:fe05:620]:49115" \
	"told the host rendezvous at [<v6-1>]:49115"

check "a global v4 endpoint keeps its port and loses its address" \
	"path: srflx 203.0.113.9:41234 chosen" \
	"path: srflx <v4-1>:41234 chosen"

check "the private ranges are left alone" \
	"node 192.168.5.164:6881 and 10.1.2.3:5 and 172.16.0.1:1" \
	"node 192.168.5.164:6881 and 10.1.2.3:5 and 172.16.0.1:1"

check "loopback, link-local, ULA and multicast are left alone" \
	"[::1]:9000 127.0.0.1:9000 [fe80::1%eth0]:5353 [fd00::1]:1 224.0.0.251" \
	"[::1]:9000 127.0.0.1:9000 [fe80::1%eth0]:5353 [fd00::1]:1 224.0.0.251"

# Which lines name the same place is most of what a tail is read for, so the
# alias has to hold across a line and tell two addresses apart.
check "one address reads as one alias, two as two" \
	"[2a01:db8::1]:1 then [2a01:db8::1]:2 then [2a02:db8::9]:3" \
	"[<v6-1>]:1 then [<v6-1>]:2 then [<v6-2>]:3"

check "a clock is not an address" \
	"15:24:03 host: reaped a worker" \
	"15:24:03 host: reaped a worker"

check "a line with nothing in it comes back whole" \
	"client 1 never finished its session:" \
	"client 1 never finished its session:"

if [ "$fail" = 0 ]; then
	echo "redact: addresses masked, everything else intact"
fi
exit $fail
