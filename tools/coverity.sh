#!/bin/sh
# Drive the Coverity Scan build tool and the upload, from CI and by hand.
#
# Usage: tools/coverity.sh tool [--yes]
#        tools/coverity.sh md5
#        tools/coverity.sh capture <dir> -- <command...>
#        tools/coverity.sh check <dir>
#        tools/coverity.sh submit <dir> [--version <v>] --description <d>
#
# tool prints the directory holding cov-build: COVERITY_TOOL_DIR/bin when it
# is there, else the one on PATH, else it downloads Scan's tarball into
# COVERITY_TOOL_DIR, which takes --yes because that is about 1 GB down and
# over 2 GB unpacked. md5 prints the tarball's md5 as Scan publishes it, the
# cache key for the tool. capture runs the command under cov-build and then
# check, which reads the build log and refuses a capture with no compilation
# units or with a failed one. submit tars the intermediate directory and posts
# it to Scan.
#
# Environment: COVERITY_SCAN_TOKEN (the project token: tool, md5, submit),
# COVERITY_SCAN_EMAIL (submit), COVERITY_SCAN_PROJECT (the Scan project name,
# default the origin remote's owner/repo), COVERITY_TOOL_DIR (default
# ${XDG_CACHE_HOME:-$HOME/.cache}/coverity), COVERITY_SCAN_URL (default
# https://scan.coverity.com).
set -eu

scan_url=${COVERITY_SCAN_URL:-https://scan.coverity.com}
tool_dir=${COVERITY_TOOL_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/coverity}

die() {
	echo "coverity.sh: $*" >&2
	exit 1
}

usage() {
	sed -n '2,/^set -eu/{/^set -eu/d; s/^# \{0,1\}//p}' "$0" >&2
	exit 1
}

token_need() {
	[ -n "${COVERITY_SCAN_TOKEN:-}" ] || die "COVERITY_SCAN_TOKEN is not set"
}

project_get() {
	if [ -n "${COVERITY_SCAN_PROJECT:-}" ]; then
		echo "$COVERITY_SCAN_PROJECT"
		return
	fi
	url=$(git remote get-url origin 2>/dev/null) ||
		die "COVERITY_SCAN_PROJECT is not set and there is no origin remote"
	url=${url%.git}
	url=${url%/}
	rest=${url%/*}
	echo "${rest##*[/:]}/${url##*/}"
}

# Only the characters a GitHub repository name can carry beyond what a URL
# query takes as-is: the slash, and a space should the project be renamed.
project_encode() {
	echo "$1" | sed -e 's:/:%2F:g' -e 's/ /%20/g'
}

md5_fetch() {
	token_need
	curl -fsS --retry 5 --retry-delay 5 \
		--data-urlencode "token=$COVERITY_SCAN_TOKEN" \
		--data-urlencode "project=$(project_get)" \
		--data "md5=1" \
		"$scan_url/download/linux64"
}

tool_find() {
	if [ -x "$tool_dir/bin/cov-build" ]; then
		echo "$tool_dir/bin"
		return 0
	fi
	p=$(command -v cov-build 2>/dev/null) || return 1
	dirname "$p"
}

cmd_tool() {
	yes=
	[ "${1:-}" = --yes ] && yes=1
	if bin=$(tool_find); then
		echo "$bin"
		return 0
	fi
	md5=$(md5_fetch)
	[ -n "$yes" ] || die "no cov-build under $tool_dir or on PATH; the" \
		"download is about 1 GB and over 2 GB unpacked, rerun with --yes" \
		"to fetch it into $tool_dir"
	mkdir -p "$tool_dir"
	tgz="$tool_dir/cov-analysis.tgz"
	curl -fsS --retry 5 --retry-delay 5 -o "$tgz" \
		--data-urlencode "token=$COVERITY_SCAN_TOKEN" \
		--data-urlencode "project=$(project_get)" \
		"$scan_url/download/linux64"
	echo "$md5  $tgz" | md5sum -c - >/dev/null ||
		die "the downloaded tool does not match the md5 Scan publishes ($md5)"
	tar xzf "$tgz" -C "$tool_dir" --strip-components=1
	rm -f "$tgz"
	echo "$md5" > "$tool_dir/.md5"
	[ -x "$tool_dir/bin/cov-build" ] ||
		die "no bin/cov-build after unpacking into $tool_dir"
	echo "$tool_dir/bin"
}

cmd_md5() {
	md5_fetch
	echo
}

# The last summary line is cumulative over every cov-build run into the
# directory, so one check covers a capture assembled in several steps.
# cov-build exits 0 with nothing emitted, which is why the count is read.
cmd_check() {
	dir=${1:?usage: coverity.sh check <dir>}
	log="$dir/build-log.txt"
	[ -f "$log" ] || die "$log does not exist; nothing was captured"
	summary=$(sed -n 's/.*> \([0-9][0-9]*\) C\/C++ compilation units (\([0-9][0-9]*\)%) are ready for analysis.*/\1 \2/p' "$log" |
		tail -1)
	[ -n "$summary" ] ||
		die "$log has no compilation-unit summary; cov-build did not finish"
	units=${summary% *}
	pct=${summary#* }
	[ "$units" -gt 0 ] || die "cov-build emitted no compilation units"
	[ "$pct" -eq 100 ] ||
		die "only $pct% of $units compilation units are ready; a unit failed, see $log"
	echo "coverity: $units compilation units ready for analysis"
}

cmd_capture() {
	dir=${1:?usage: coverity.sh capture <dir> -- <command...>}
	shift
	[ "${1:-}" = -- ] && shift
	[ $# -gt 0 ] || die "capture: no command given after --"
	bin=$(tool_find) ||
		die "no cov-build under $tool_dir or on PATH; run coverity.sh tool first"
	rc=0
	"$bin/cov-build" --dir "$dir" "$@" || rc=$?
	cmd_check "$dir"
	return $rc
}

cmd_submit() {
	dir=${1:?usage: coverity.sh submit <dir> [--version <v>] --description <d>}
	shift
	version=
	description=
	while [ $# -gt 0 ]; do
		case $1 in
		--version) version=$2; shift 2 ;;
		--description) description=$2; shift 2 ;;
		*) die "submit: unknown argument $1" ;;
		esac
	done
	[ -n "$description" ] || die "submit: --description is required"
	token_need
	[ -n "${COVERITY_SCAN_EMAIL:-}" ] || die "COVERITY_SCAN_EMAIL is not set"
	[ "$(basename "$dir")" = cov-int ] ||
		die "Scan takes the intermediate directory under the name cov-int, not $(basename "$dir")"
	cmd_check "$dir" >/dev/null
	[ -n "$version" ] || version=$(git describe --tags --always) ||
		die "submit: no --version and git describe failed"
	tgz="$dir.tgz"
	tar czf "$tgz" -C "$(dirname "$dir")" cov-int
	size=$(wc -c < "$tgz")
	if [ "$size" -gt 524288000 ]; then
		rm -f "$tgz"
		die "cov-int.tgz is $size bytes, above the 500 MB the form upload takes;" \
			"this size needs the init, PUT and enqueue flow the project page describes"
	fi
	body="$tgz.response"
	status=$(curl -sS --retry 3 --retry-delay 10 -o "$body" -w '%{http_code}' \
		--form-string "token=$COVERITY_SCAN_TOKEN" \
		--form-string "email=$COVERITY_SCAN_EMAIL" \
		--form "file=@$tgz" \
		--form-string "version=$version" \
		--form-string "description=$description" \
		"$scan_url/builds?project=$(project_encode "$(project_get)")")
	cat "$body"
	echo
	rm -f "$tgz" "$body"
	case $status in
	2??) echo "coverity: build submitted, $size bytes, version $version" ;;
	*) die "upload failed with HTTP $status" ;;
	esac
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
tool) cmd_tool "$@" ;;
md5) cmd_md5 ;;
capture) cmd_capture "$@" ;;
check) cmd_check "$@" ;;
submit) cmd_submit "$@" ;;
*) usage ;;
esac
