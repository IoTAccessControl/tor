#include "feature/ewfd/ewfd_utils.h"
#include <stdarg.h>
#include <stdio.h>

#include "lib/log/log.h"

void ewfd_log(const char *fmt, ...) {
	char log_text[256] = {0};
	va_list args;
	va_start(args, fmt);
	vsprintf(log_text, fmt, args);
	va_end(args);
	log_my(LD_GENERAL, "%s -> %s:%d", log_text, __FILE__, __LINE__);
}