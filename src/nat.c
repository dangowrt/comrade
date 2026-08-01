#include <errno.h>
#include <stddef.h>

#include "nat.h"

struct nat_agent *nat_agent_create(void)
{
	errno = ENOSYS;
	return NULL;
}

void nat_agent_free(struct nat_agent *agent)
{
	(void)agent;
}
