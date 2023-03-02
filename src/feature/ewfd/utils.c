#include "feature/ewfd/utils.h"
#include <stdarg.h>
#include <stdio.h>

#include "lib/log/log.h"


void ewfd_my_log_caller(const char *fn, const char *fi, int li, const char *format, ...) {
	char my_log[128] = {0};
	
	va_list args;
	va_start(args, format);
	vsprintf(my_log, format, args);
	va_end(args);
	log_fn_(LOG_LAST_LEV, LD_GENERAL, __FUNCTION__, "%-100s -> %s:%d(%s)", my_log, fi, li, fn);
}