/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "appdir.h"
#include "oscompat.h"
#include "stunlist.h"
#include "stun_bundle.inc"		/* static const char *const stun_bundle[] */

/*
 * The RFC 5780-capable list from always-online-stun. Fetched only on an
 * explicit `comrade stun-update`, never automatically. GitHub-hosted, which the
 * project otherwise avoids, but the fetch is opt-in and one-off.
 */
#define STUN_UPDATE_URL \
	"https://raw.githubusercontent.com/pradt2/always-online-stun/" \
	"master/valid_nat_testing_hosts.txt"

const char *stunlist_path(void)
{
	static char path[600];

	snprintf(path, sizeof(path), "%s/stun_servers.txt", appdir_data());
	return path;
}

const char *stunlist_url(void)
{
	return STUN_UPDATE_URL;
}

/* A "host:port" line worth keeping: no whitespace, has a dot and a colon, and
 * no angle bracket (so a fetched HTML error page yields nothing). */
static int line_ok(const char *s)
{
	return *s && *s != '#' && strchr(s, ':') && strchr(s, '.') &&
	       !strchr(s, ' ') && !strchr(s, '\t') && !strchr(s, '<');
}

/* Parse "host:port" lines from f into a malloc'd array; count in *n. */
static char **parse_lines(FILE *f, int *n)
{
	char **arr = NULL;
	int cap = 0, cnt = 0;
	char line[256];

	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		size_t len;

		while (*s == ' ' || *s == '\t')
			s++;
		len = strlen(s);
		while (len && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
			       s[len - 1] == ' ' || s[len - 1] == '\t'))
			s[--len] = '\0';
		if (!line_ok(s))
			continue;
		if (cnt == cap) {
			int ncap = cap ? cap * 2 : 16;
			char **na = realloc(arr, (size_t)ncap * sizeof(*na));

			if (!na) {
				stunlist_free(arr, cnt);
				return NULL;
			}
			arr = na;
			cap = ncap;
		}
		arr[cnt] = strdup(s);
		if (!arr[cnt]) {
			stunlist_free(arr, cnt);
			return NULL;
		}
		cnt++;
	}
	*n = cnt;
	return arr;
}

/* Copy the built-in bundle into a fresh array. */
static char **load_bundle(int *n)
{
	int bn = (int)(sizeof(stun_bundle) / sizeof(stun_bundle[0]));
	char **arr = malloc((size_t)bn * sizeof(*arr));
	int i;

	if (!arr) {
		*n = 0;
		return NULL;
	}
	for (i = 0; i < bn; i++) {
		arr[i] = strdup(stun_bundle[i]);
		if (!arr[i]) {
			stunlist_free(arr, i);
			*n = 0;
			return NULL;
		}
	}
	*n = bn;
	return arr;
}

char **stunlist_load(int *n)
{
	FILE *f = fopen(stunlist_path(), "r");

	*n = 0;
	if (f) {
		int fn = 0;
		char **arr = parse_lines(f, &fn);

		fclose(f);
		if (arr && fn > 0) {
			*n = fn;
			return arr;
		}
		stunlist_free(arr, fn);	/* empty/garbage: fall back to bundle */
	}
	return load_bundle(n);
}

void stunlist_free(char **list, int n)
{
	int i;

	if (!list)
		return;
	for (i = 0; i < n; i++)
		free(list[i]);
	free(list);
}

/* Fetch url to out, trying wget then curl (uclient-fetch provides wget;
 * Windows 10+ ships curl.exe in System32). */
static int run_fetch(const char *url, const char *out)
{
	char *wget[] = { "wget", "-q", "-O", (char *)out, (char *)url, NULL };
	char *curl[] = { "curl", "-fsSL", "-o", (char *)out, (char *)url, NULL };

	if (os_spawn_wait(wget) == 0)
		return 0;
	if (os_spawn_wait(curl) == 0)
		return 0;
	return -1;
}

int stunlist_update(int *count)
{
	const char *path = stunlist_path();
	char tmp[610];
	char **list;
	int n = 0;
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fprintf(stderr,
		"Privacy note: the upstream list is not curated by hosting\n"
		"provider. Unlike the built-in default, it may include STUN\n"
		"servers hosted by large cloud/CDN operators (AWS, Google,\n"
		"Cloudflare, Microsoft, ...); querying those reveals your address\n"
		"to them during NAT discovery.\n\n");
	fprintf(stderr, "comrade: fetching STUN servers from\n  %s\n",
		STUN_UPDATE_URL);
	if (run_fetch(STUN_UPDATE_URL, tmp)) {
		fprintf(stderr, "comrade: fetch failed (need wget or curl)\n");
		remove(tmp);
		return -1;
	}
	f = fopen(tmp, "r");
	list = f ? parse_lines(f, &n) : NULL;
	if (f)
		fclose(f);
	if (!list || n == 0) {
		fprintf(stderr, "comrade: fetched list was empty or unparseable\n");
		stunlist_free(list, n);
		remove(tmp);
		return -1;
	}
	stunlist_free(list, n);
	if (os_rename_replace(tmp, path)) {
		fprintf(stderr, "comrade: could not save %s\n", path);
		remove(tmp);
		return -1;
	}
	if (count)
		*count = n;
	return 0;
}
