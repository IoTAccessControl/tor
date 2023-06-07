#include "feature/ewfd/ewfd_ticker.h"
#include "ext/timeouts/timeout.h"
#include "lib/defs/time.h"
#include <bits/types/struct_timeval.h>

void ewfd_init_ticker(tor_timer_t **ticker, timer_cb_fn_t cb, void *arg) {
	if (*ticker == NULL) {
		*ticker = timer_new(cb, arg);
	} else { // set timer again if disabled
		timer_disable(*ticker);
		timer_set_cb(*ticker, cb, arg);
	}
}

void ewfd_remove_ticker(tor_timer_t **ticker) {
	if (*ticker != NULL) {
		timer_disable(*ticker);
		*ticker = NULL;
	}
}

void ewfd_schedule_ticker(tor_timer_t *ticker, uint32_t next_ti_ms) {
	struct timeval timeout;
	timeout.tv_sec = next_ti_ms * 1000 / TOR_USEC_PER_SEC;
	timeout.tv_usec = (next_ti_ms * 1000) % TOR_USEC_PER_SEC;
	timer_schedule(ticker, &timeout);
}
