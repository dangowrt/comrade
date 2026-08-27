# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
#
# redact -- a filter for anything a test prints when it fails. Sourced, not run.
#
# A red e2e says why by printing the tail of a debug log, and those lines carry
# whatever endpoint the run was working with: this machine's address as a STUN
# reply gave it, the node a rendezvous landed on, where a peer was reached. A
# workflow run publishes that to anyone who opens the log.
#
# A tail is read for the shape rather than the digits, so each address becomes
# <v4-N>/<v6-N>, numbered in order of first appearance, and the port beside it
# is kept. Loopback, link-local, ULA, multicast and the private v4 ranges stay
# as they are: they are the substance of the LAN tests and describe nobody.

redact() {
	awk '
	function count(s, c,   i, k) {
		k = 0
		for (i = 1; i <= length(s); i++)
			if (substr(s, i, 1) == c)
				k++
		return k
	}
	function local4(a,   p) {
		split(a, p, ".")
		if (p[1] + 0 > 255 || p[2] + 0 > 255 ||
		    p[3] + 0 > 255 || p[4] + 0 > 255)
			return 1
		if (p[1] + 0 == 127 || p[1] + 0 == 10 || p[1] + 0 == 0)
			return 1
		if (p[1] + 0 == 192 && p[2] + 0 == 168)
			return 1
		if (p[1] + 0 == 172 && p[2] + 0 >= 16 && p[2] + 0 <= 31)
			return 1
		if (p[1] + 0 == 169 && p[2] + 0 == 254)
			return 1
		if (p[1] + 0 >= 224)
			return 1
		return 0
	}
	function local6(a,   l) {
		l = tolower(a)
		if (l == "::" || l == "::1")
			return 1
		if (l ~ /^fe[89ab]/ || l ~ /^f[cd]/ || l ~ /^ff/)
			return 1
		return 0
	}
	function alias(a, fam) {
		if (!(a in seen)) {
			n++
			seen[a] = "<v" fam "-" n ">"
		}
		return seen[a]
	}
	{
		rest = $0
		out = ""
		while (match(rest, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F]*(:[0-9a-fA-F]*)+/)) {
			tok = substr(rest, RSTART, RLENGTH)
			out = out substr(rest, 1, RSTART - 1)
			rest = substr(rest, RSTART + RLENGTH)
			if (index(tok, ":") > 0) {
				if ((index(tok, "::") > 0 || count(tok, ":") >= 4) &&
				    !local6(tok))
					out = out alias(tok, 6)
				else
					out = out tok
			} else if (!local4(tok)) {
				out = out alias(tok, 4)
			} else {
				out = out tok
			}
		}
		print out rest
	}'
}

# Everything the caller prints from here on goes through the filter. A named
# pipe rather than a process substitution, which is not POSIX: the filter reads
# the pipe and writes to the output ctest collects, so ctest still sees one
# stream in the order it was written, and still waits for all of it. Both
# streams are merged, since a failure is read as one story either way.
redact_output() {
	_rf="$(mktemp -u)"
	mkfifo "$_rf" 2>/dev/null || return 0
	redact < "$_rf" &
	exec > "$_rf" 2>&1
	rm -f "$_rf"
}
