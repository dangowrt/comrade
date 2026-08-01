#include <errno.h>
#include <stddef.h>

#include "sig.h"

struct sig_backend *sig_bep44_create(void)
{
	errno = ENOSYS;
	return NULL;
}
