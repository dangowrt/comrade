#ifndef COMRADE_BEP44_H
#define COMRADE_BEP44_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define BEP44_MAX_VALUE 1000
#define BEP44_MAX_SALT 64

struct bep44_engine;

typedef void bep44_put_cb(void *arg, int stored);
typedef void bep44_get_cb(void *arg, const uint8_t *v, size_t v_len, int64_t seq);

struct bep44_engine *bep44_create(const uint8_t myid[20], int s4, int s6);
void bep44_free(struct bep44_engine *e);
int bep44_bootstrap_add(struct bep44_engine *e, const struct sockaddr *sa,
			socklen_t salen);
int bep44_seed_add(struct bep44_engine *e, const uint8_t id[20],
		   const struct sockaddr *sa, socklen_t salen);
int bep44_input(struct bep44_engine *e, const uint8_t *buf, size_t len);
int bep44_periodic(struct bep44_engine *e, int *timeout_ms);
int bep44_put(struct bep44_engine *e, const uint8_t sk[64], const uint8_t pk[32],
	      const char *salt, const uint8_t *v, size_t v_len, int64_t seq,
	      bep44_put_cb *cb, void *arg);
int bep44_get(struct bep44_engine *e, const uint8_t pk[32], const char *salt,
	      bep44_get_cb *cb, void *arg);

size_t bep44_sig_buffer(uint8_t *dst, size_t dst_len, const char *salt,
			int64_t seq, const uint8_t *v, size_t v_len);
void bep44_target(uint8_t target[20], const uint8_t pk[32], const char *salt);

#endif
