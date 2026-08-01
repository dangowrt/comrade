#include <errno.h>

#include "sshd.h"

int sshd_run(const struct token *tok, int fd)
{
	(void)tok;
	(void)fd;
	errno = ENOSYS;
	return -1;
}
