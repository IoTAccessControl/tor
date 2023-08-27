
#include "feature/ewfd/ewfd_conf.h"
#include "feature/ewfd/ewfd.h"
#include "feature/ewfd/circuit_padding.h"
#include "feature/ewfd/ewfd_unit.h"
#include "feature/ewfd/utils.h"

#include "lib/ebpf/ewfd-defense/src/front_code.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/smartlist_core/smartlist_foreach.h"

#include <stdint.h>
#include <string.h>

/*
1. init code
2. padding code
3. schedule code
*/
smartlist_t *ewfd_code_cache = NULL;

#define CODE_FRONT_INIT "front_init_code"
#define CODE_FRONT_RUN "front_run_code"
#define CODE_FRONT_SCHEDULE "front_schedule_code"

void init_ewfd_code_cache(void) {
	if (ewfd_code_cache == NULL) {
		ewfd_code_cache = smartlist_new();
	}

	// add front init code
	ewfd_code_st *front_init = (ewfd_code_st *) tor_malloc_zero(sizeof(ewfd_code_st) + sizeof(ewfd_front_padding_init));
	front_init->code_type = EWFD_CODE_TYPE_INIT;
	front_init->code_len = sizeof(ewfd_front_padding_init) - 1;
	strcpy(front_init->name, CODE_FRONT_INIT);
	memcpy(front_init->code, ewfd_front_padding_init, front_init->code_len);
	smartlist_add(ewfd_code_cache, front_init);

	// add front run-tick code
	ewfd_code_st *front_run = (ewfd_code_st *) tor_malloc_zero(sizeof(ewfd_code_st) + sizeof(ewfd_front_padding_init));
	front_run->code_type = EWFD_CODE_TYPE_MAIN;
	front_run->code_len = sizeof(ewfd_front_padding_tick) - 1;
	strcpy(front_run->name, CODE_FRONT_RUN);
	memcpy(front_run->code, ewfd_front_padding_tick, front_run->code_len);
	smartlist_add(ewfd_code_cache, front_run);

	// add front schedule code
	// + sizeof(ewfd_front_padding_init) - 1
	ewfd_code_st *front_schedule = (ewfd_code_st *) tor_malloc_zero(sizeof(ewfd_code_st));
	front_schedule->code_type = EWFD_CODE_TYPE_MAIN;
	front_schedule->code_len = sizeof(ewfd_front_schedule_1) - 1;
	strcpy(front_schedule->name, CODE_FRONT_SCHEDULE);
	memcpy(front_schedule->code, ewfd_front_schedule_1, front_schedule->code_len);
	smartlist_add(ewfd_code_cache, front_schedule);
}


void free_ewfd_code_cache(void) {
	if (ewfd_code_cache != NULL) {
		SMARTLIST_FOREACH(ewfd_code_cache, ewfd_code_st*, code, tor_free(code));
		smartlist_free(ewfd_code_cache);
	}
}

static ewfd_code_st* ewfd_code_cache_get(const char *name) {
	SMARTLIST_FOREACH_BEGIN(ewfd_code_cache, ewfd_code_st*, code) {
		if (strcmp(code->name, name) == 0) {
			return code;
		}
	} SMARTLIST_FOREACH_END(code);
	return NULL;
}

ewfd_padding_conf_st* demo_get_front_schedule_unit_conf(void) {
	ewfd_code_st *front_schedule = ewfd_code_cache_get(CODE_FRONT_SCHEDULE);
	if (front_schedule == NULL) {
		return NULL;
	}

	ewfd_padding_conf_st *schedule_unit = tor_malloc_zero(sizeof(ewfd_framework_st));
	schedule_unit->unit_uuid = 2;
	schedule_unit->unit_type = EWFD_UNIT_SCHEDULE;
	schedule_unit->target_hopnum = 2;
	schedule_unit->tick_interval = MIN_EWFD_SCHEDULE_GAP_US;
	schedule_unit->initial_hop = EWFD_NODE_ROLE_CLIENT; // client only
	schedule_unit->init_code = NULL;
	schedule_unit->main_code = front_schedule;
	smartlist_add(ewfd_client_conf->client_unit_confs, schedule_unit);

	return schedule_unit;
}

ewfd_padding_conf_st* demo_get_front_padding_unit_conf(void) {
	ewfd_code_st *front_init = ewfd_code_cache_get(CODE_FRONT_INIT);
	ewfd_code_st *front_run = ewfd_code_cache_get(CODE_FRONT_RUN);
	if (front_init == NULL || front_run == NULL) {
		return NULL;
	}

	ewfd_padding_conf_st *padding_unit = tor_malloc_zero(sizeof(ewfd_padding_conf_st));
	padding_unit->unit_uuid = 1;
	padding_unit->unit_type = EWFD_UNIT_PADDING;
	padding_unit->target_hopnum = 2;
	padding_unit->tick_interval = MIN_EWFD_TICK_GAP_MS;
	padding_unit->initial_hop = EWFD_NODE_ROLE_CLIENT; // client only
	padding_unit->init_code = front_init;
	padding_unit->main_code = front_run;

	return padding_unit;
}