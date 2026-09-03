#!/bin/sh
# Emit the runtime options for an instrumented run, for eval:
#
#   eval "$(tests/sanenv.sh address "$PWD/san-logs")"
#
# The same thing CI does, so a failure there is reproducible here by running
# the same line. Two choices in it are worth knowing about.
#
# log_path sends reports to files instead of stderr. The e2e tests drive
# comrade as a CHILD process, and a child's report goes to a stderr the harness
# captures into a temporary directory and then deletes -- so a run judged from
# ctest's output alone sees nothing and passes. Files survive that.
#
# detect_leaks is asked for only where there is a LeakSanitizer to ask. Darwin
# has none, and setting it there makes the runtime refuse to start, which would
# read as every test failing for reasons having nothing to do with the code.
set -u

mode="${1:?usage: sanenv.sh <none|address|thread> <log-dir>}"
dir="${2:?usage: sanenv.sh <none|address|thread> <log-dir>}"
supp_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -s)" in
Darwin) leaks=0 ;;
*)      leaks=1 ;;
esac

case "$mode" in
none)
	;;
address)
	echo "export ASAN_OPTIONS='detect_leaks=${leaks}:abort_on_error=0:log_path=${dir}/asan'"
	echo "export LSAN_OPTIONS='log_path=${dir}/lsan'"
	echo "export UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1:log_path=${dir}/ubsan'"
	;;
thread)
	# halt_on_error stays off: one race must not stop the run, or the first
	# finding hides every other one and each round costs a whole CI cycle.
	echo "export TSAN_OPTIONS='halt_on_error=0:suppressions=${supp_dir}/tsan.supp:log_path=${dir}/tsan'"
	;;
*)
	echo "sanenv: unknown mode '$mode'" >&2
	exit 2
	;;
esac
