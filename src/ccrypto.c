/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>

#include "ccrypto.h"

/*
 * A backend missing a primitive is a build that cannot be used, not a session
 * that can be declined: the same call fails identically everywhere, and the
 * only alternative to stopping is deriving from whatever the failed call left
 * behind. CMakeLists.txt refuses such a backend at configure time, so
 * reaching here means the compiled-and-linked probe passed and the primitive
 * went missing afterwards -- a provider unloaded, or an allocation the crypto
 * library needed. Say which primitive, so the answer is a package to install
 * rather than a fingerprint mismatch to chase.
 */
void cc_fatal(const char *what)
{
	fprintf(stderr, "comrade: this build's crypto backend cannot compute "
		"%s, which comrade's wire format requires\n", what);
	fflush(stderr);
	abort();
}
