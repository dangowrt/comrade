/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "nsfacts.h"

/* [0] is IPv4, [1] is IPv6. */
static int fam_idx(int family)
{
	return family == 6 ? 1 : 0;
}

static size_t addr_len(int family)
{
	return family == 6 ? 16 : 4;
}

void nsfacts_init(struct nsfacts *f)
{
	memset(f, 0, sizeof(*f));
}

void nsfacts_post(struct nsfacts *f, int kind, int family, uint32_t epoch)
{
	int i = fam_idx(family);

	if (kind == NSF_ROUNDTRIP) {
		f->rt[i] = 1;
		f->rt_epoch[i] = epoch;
	} else if (kind == NSF_PROBE_DONE) {
		f->done[i] = 1;
		f->done_epoch[i] = epoch;
	}
}

void nsfacts_post_addr(struct nsfacts *f, int family, uint32_t epoch,
		       const uint8_t *addr, const char *text)
{
	size_t len = addr_len(family);
	struct nsfact *e;
	int i;

	for (i = 0; i < f->n; i++) {
		e = &f->q[i];
		if (e->kind == NSF_ADDR && e->family == family &&
		    e->epoch == epoch && !memcmp(e->addr, addr, len))
			return;
	}
	if (f->n >= NSFACTS_MAX)
		return;
	e = &f->q[f->n++];
	memset(e, 0, sizeof(*e));
	e->kind = NSF_ADDR;
	e->family = family;
	e->epoch = epoch;
	memcpy(e->addr, addr, len);
	snprintf(e->text, sizeof(e->text), "%s", text);
}

/* One of the per-family slots into the caller's array. */
static void emit(struct nsfact *out, int kind, int i, uint32_t epoch)
{
	memset(out, 0, sizeof(*out));
	out->kind = kind;
	out->family = i ? 6 : 4;
	out->epoch = epoch;
}

int nsfacts_take(struct nsfacts *f, struct nsfact *out, int max)
{
	int n = 0, i, kept;

	for (i = 0; i < 2; i++) {
		if (!f->rt[i] || n >= max)
			continue;
		emit(&out[n++], NSF_ROUNDTRIP, i, f->rt_epoch[i]);
		f->rt[i] = 0;
	}
	for (i = 0; i < f->n && n < max; i++)
		out[n++] = f->q[i];
	kept = f->n - i;
	if (kept > 0)
		memmove(f->q, &f->q[i], sizeof(f->q[0]) * (size_t)kept);
	f->n = kept;
	for (i = 0; i < 2; i++) {
		if (!f->done[i] || n >= max)
			continue;
		emit(&out[n++], NSF_PROBE_DONE, i, f->done_epoch[i]);
		f->done[i] = 0;
	}
	return n;
}
