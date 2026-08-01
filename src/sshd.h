#ifndef COMRADE_SSHD_H
#define COMRADE_SSHD_H

struct token;

int sshd_run(const struct token *tok, int fd);

#endif
