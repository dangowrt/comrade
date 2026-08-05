/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <string.h>

#include "host.h"
#include "token.h"

static int usage(int ret)
{
	fprintf(stderr,
		"usage: comrade            start a shared session\n"
		"       comrade <token>    connect to a shared session\n"
		"       comrade show       print the tokens of the running session\n");
	return ret;
}

static int session_connect(const char *arg)
{
	struct token tok;

	if (token_decode(&tok, arg)) {
		fprintf(stderr, "comrade: invalid token\n");
		return 1;
	}

	fprintf(stderr, "comrade: connecting is not implemented yet\n");
	return 1;
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return host_run();
	if (argc != 2)
		return usage(1);
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		return usage(0);
	if (!strcmp(argv[1], "show"))
		return host_show();

	return session_connect(argv[1]);
}
