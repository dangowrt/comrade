#include <errno.h>

#include "stream.h"

int stream_open(int udp_fd)
{
	(void)udp_fd;
	errno = ENOSYS;
	return -1;
}
