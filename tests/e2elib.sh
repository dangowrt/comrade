# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
#
# What every harness script needs, whether or not it builds a swarm. Sourced,
# not run.

# A wait bound of N, scaled by the run's slowness: an instrumented or loaded
# lane is many times slower, so its polls wait proportionally longer.
e2e_loops() {
	echo $(( ${1:-1} * ${COMRADE_E2E_TIMEOUT_SCALE:-1} ))
}
