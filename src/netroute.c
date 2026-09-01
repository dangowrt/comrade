/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include "wsock.h"
#include <string.h>

#include "netroute.h"

/*
 * Documentation addresses, so nothing is sent anywhere that exists even if a
 * kernel ever decided to send on connect: 2001:db8::/32 and 192.0.2.0/24 are
 * reserved for exactly this and are routed nowhere.
 */
int net_source_addr(int af, char *text, size_t textlen, uint8_t *raw,
		    int *rawlen)
{
	static const char *probe6 = "2001:db8::1";
	static const char *probe4 = "192.0.2.1";
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	char scratch[64];
	sock_t fd;
	int rc = -1;

	if (!text) {
		text = scratch;
		textlen = sizeof(scratch);
	}
	if (wsock_init())
		return -1;
	fd = socket(af, SOCK_DGRAM, 0);
	if (!sock_valid(fd))
		return -1;
	memset(&ss, 0, sizeof(ss));
	if (af == AF_INET6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;

		a->sin6_family = AF_INET6;
		a->sin6_port = htons(9);
		if (inet_pton(AF_INET6, probe6, &a->sin6_addr) != 1 ||
		    connect(fd, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;

		a->sin_family = AF_INET;
		a->sin_port = htons(9);
		if (inet_pton(AF_INET, probe4, &a->sin_addr) != 1 ||
		    connect(fd, (struct sockaddr *)a, sizeof(*a)))
			goto out;
	}
	memset(&ss, 0, sizeof(ss));
	if (getsockname(fd, (struct sockaddr *)&ss, &slen))
		goto out;
	if (af == AF_INET6) {
		struct in6_addr *a6 = &((struct sockaddr_in6 *)&ss)->sin6_addr;

		rc = inet_ntop(AF_INET6, a6, text, (socklen_t)textlen) ? 0 : -1;
		if (!rc && raw && rawlen) {
			memcpy(raw, a6, 16);
			*rawlen = 16;
		}
	} else {
		struct in_addr *a4 = &((struct sockaddr_in *)&ss)->sin_addr;

		rc = inet_ntop(AF_INET, a4, text, (socklen_t)textlen) ? 0 : -1;
		if (!rc && raw && rawlen) {
			memcpy(raw, a4, 4);
			*rawlen = 4;
		}
	}
out:
	sock_close(fd);
	return rc;
}

int net_family_routed(int af)
{
	return net_source_addr(af, NULL, 0, NULL, NULL) == 0;
}
