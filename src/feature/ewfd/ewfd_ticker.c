#include "feature/ewfd/ewfd_ticker.h"
#include "ext/timeouts/timeout.h"
#include "lib/defs/time.h"
#include <bits/types/struct_timeval.h>
#include "feature/ewfd/circuit_padding.h"

// #define USE_TEMP_LOG
#include "feature/ewfd/debug.h"

int total_ewfd_timer = 0;
int released_ewfd_timer = 0;

void ewfd_init_ticker(tor_timer_t **ticker, timer_cb_fn_t cb, void *arg) {
	if (*ticker == NULL) {
		*ticker = timer_new(cb, arg);
		total_ewfd_timer++;
		ewfd_padding_runtime_st *ewfd_rt = (ewfd_padding_runtime_st *) arg;
		EWFD_TEMP_LOG("init_ticker: %d--------- circ: %u", total_ewfd_timer, ewfd_get_circuit_id(ewfd_rt->on_circ));
	} else { // set timer again if disabled
		timer_disable(*ticker);
		timer_set_cb(*ticker, cb, arg);
		EWFD_TEMP_LOG("init_ticker---------reuse");
	}
}

void ewfd_remove_ticker(tor_timer_t **ticker) {
	// ticker is not released here, can resue it latter
	if (*ticker != NULL) {
		timer_disable(*ticker);
		// fix bug: *ticker = NULL;
	}
}

void ewfd_schedule_ticker(tor_timer_t *ticker, uint32_t next_ti_ms) {
	struct timeval timeout;
	timeout.tv_sec = next_ti_ms * 1000 / TOR_USEC_PER_SEC;
	timeout.tv_usec = (next_ti_ms * 1000) % TOR_USEC_PER_SEC;
	timer_schedule(ticker, &timeout);
}

void ewfd_free_ticker(tor_timer_t **ticker) {
	if (*ticker != NULL) {
		timer_free(*ticker);
		released_ewfd_timer++;
		EWFD_TEMP_LOG("free_ticker---------remain: %d", released_ewfd_timer);
	} else {
		EWFD_TEMP_LOG("free_ticker---------null");
	}
}