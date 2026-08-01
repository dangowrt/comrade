#ifndef COMRADE_NAT_H
#define COMRADE_NAT_H

#include <stddef.h>
#include <stdint.h>

#define NAT_SDP_MAX 4096

struct nat_agent;

typedef void nat_cb_local_sdp(void *arg, const char *sdp);
typedef void nat_cb_state(void *arg, int connected, int failed);
typedef void nat_cb_recv(void *arg, const uint8_t *data, size_t len);

struct nat_config {
	const char *stun_host;
	uint16_t stun_port;
	nat_cb_local_sdp *on_local_sdp;
	nat_cb_state *on_state;
	nat_cb_recv *on_recv;
	void *arg;
};

struct nat_agent *nat_create(const struct nat_config *cfg);
void nat_destroy(struct nat_agent *a);

int nat_gather(struct nat_agent *a);
int nat_local_description(struct nat_agent *a, char *sdp, size_t len);
int nat_set_remote_description(struct nat_agent *a, const char *sdp);
int nat_send(struct nat_agent *a, const uint8_t *data, size_t len);

int nat_connected(struct nat_agent *a);
int nat_failed(struct nat_agent *a);

void nat_log_level(int level);

#endif
