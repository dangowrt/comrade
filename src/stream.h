#ifndef COMRADE_STREAM_H
#define COMRADE_STREAM_H

#include <stddef.h>
#include <stdint.h>

struct stream;

typedef int stream_output_fn(void *arg, const uint8_t *data, size_t len);

struct stream *stream_create(uint32_t conv, stream_output_fn *out, void *arg);
void stream_destroy(struct stream *s);

int stream_send(struct stream *s, const uint8_t *data, size_t len);
int stream_recv(struct stream *s, uint8_t *data, size_t len);
int stream_input(struct stream *s, const uint8_t *data, size_t len);

uint32_t stream_update(struct stream *s, uint32_t now_ms);
void stream_set_output(struct stream *s, stream_output_fn *out, void *arg);

#endif
