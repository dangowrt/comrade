#!/bin/sh
# Judge a sanitiser run by what the tool said, not by what the tests returned.
#
# The two are different questions and under ThreadSanitizer they give different
# answers: the instrumented binaries are slow enough to miss the timing the e2e
# tests assert while reporting nothing wrong at all. So a job may let the
# outcome go and watch this instead.
#
# Reports are collected from files rather than from ctest's output, and that is
# not a stylistic choice. The e2e tests drive comrade as a CHILD process; its
# report goes to that child's stderr, which the harness captures into a
# temporary directory and deletes on the way out. A job reading ctest's log
# alone sees none of it and passes, having checked nothing. Point the runtimes
# at a directory instead (log_path=DIR/prefix) and the reports survive.
#
# Usage: sanreport.sh <log-dir> [expected-minimum-runs]
set -u

dir="${1:?usage: sanreport.sh <log-dir> [min-runs]}"
minruns="${2:-1}"

if [ ! -d "$dir" ]; then
	echo "sanreport: $dir does not exist -- the run did not happen, or the"
	echo "sanreport: runtimes were never pointed at it. Not a pass."
	exit 2
fi

# A clean run leaves no files at all, which is indistinguishable from a run
# that never started. The marker is written by the harness that invoked ctest,
# so its absence means the wiring is broken rather than the code being clean.
if [ ! -f "$dir/.ran" ]; then
	echo "sanreport: no $dir/.ran marker -- nothing recorded that a run"
	echo "sanreport: took place. Silence here is not evidence."
	exit 2
fi
runs=$(cat "$dir/.ran" 2>/dev/null)
# Validated before it is compared. An unparseable count made the comparison
# error out and the script carry on to report "clean" -- the exact silent pass
# this file exists to refuse.
case "$runs" in
'' | *[!0-9]*)
	echo "sanreport: $dir/.ran does not hold a count ('$runs'); the harness"
	echo "sanreport: did not record how many tests ran. Not a pass."
	exit 2
	;;
esac
if [ "$runs" -lt "$minruns" ]; then
	echo "sanreport: only $runs test(s) ran, expected at least $minruns"
	exit 2
fi

all=$(find "$dir" -type f ! -name '.ran' 2>/dev/null)

# Valgrind is judged the other way round from the sanitiser runtimes. They
# write a file only when they have something to say, so no file means clean.
# Valgrind writes one every run and states its error count inside, so its files
# are read rather than counted.
logs=""
vgn=0
vgbad=""
for f in $all; do
	if grep -q "ERROR SUMMARY:" "$f" 2>/dev/null; then
		vgn=$((vgn + 1))
		if grep -q -E "ERROR SUMMARY: [1-9][0-9]* errors" "$f" 2>/dev/null; then
			vgbad="$vgbad $f"
		fi
	else
		logs="$logs $f"
	fi
done

logs=$(echo "$logs" | sed 's/^ *//')
vgbad=$(echo "$vgbad" | sed 's/^ *//')

if [ -z "$logs" ] && [ -z "$vgbad" ]; then
	if [ "$vgn" -gt 0 ]; then
		echo "sanreport: $runs test(s) ran, $vgn valgrind log(s), no errors. Clean."
	else
		echo "sanreport: $runs test(s) ran, no reports. Clean."
	fi
	exit 0
fi

if [ -n "$vgbad" ]; then
	echo "sanreport: valgrind reported errors in:"
	for f in $vgbad; do
		echo "  $f: $(grep -h -E "ERROR SUMMARY: [0-9]+" "$f" | tail -1)"
	done
	logs="$logs $vgbad"
fi

# One line per distinct finding, then the whole of the first few so a reader
# has something to act on without downloading the artefact.
echo "sanreport: findings across $runs test(s):"
# shellcheck disable=SC2086
grep -h "^SUMMARY: " $logs 2>/dev/null | sed 's/^SUMMARY: //' | sort | uniq -c | sort -rn
echo
echo "sanreport: first report in full:"
# shellcheck disable=SC2086
grep -l -E "^(WARNING|==[0-9]+==ERROR|SUMMARY)" $logs 2>/dev/null | head -1 | xargs -r sed -n '1,60p'
exit 1
