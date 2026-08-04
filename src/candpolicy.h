#ifndef COMRADE_CANDPOLICY_H
#define COMRADE_CANDPOLICY_H

#include <stddef.h>

struct cand_policy {
	int allow_private_v4;
	int allow_ula;
	int allow_overlay;
	int allow_eui64;
	int allow_linklocal;
};

void cand_policy_default(struct cand_policy *p);

int cand_addr_keep(const char *addr, int family_filter,
		   const struct cand_policy *p, int *family_out);

void cand_sdp_filter(const char *in, int family_filter,
		     const struct cand_policy *p, char *out, size_t outlen);

#endif
