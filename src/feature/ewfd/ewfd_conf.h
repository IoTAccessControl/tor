#ifndef EWFD_CONF_H_
#define EWFD_CONF_H_

#include <stdbool.h>
#include "lib/smartlist_core/smartlist_core.h"

#define MAX_EWFD_TICK_GAP_MS 500 // 500ms, queue最多调度500ms内的padding包
#define MIN_EWFD_TICK_GAP_MS 50 // 50ms, queue最小调度间隔
#define MIN_EWFD_SCHEDULE_GAP_US 500 // 500ms

enum MyPaddingType {
	EWFD_PADDING_NONE = 0,
	EWFD_PADDING_APE = 1,
	EWFD_PADDING_EBPF_TEST = 2,
	EWFD_PADDING_TARMORT = 3,
};

typedef struct ewfd_client_conf_t {
	int active_schedule_slot;
	int active_padding_slot;
	smartlist_t *client_unit_confs;
	bool need_reload;
} ewfd_client_conf_st;

extern ewfd_client_conf_st *ewfd_client_conf;

// bool parse_client_conf(void);

void init_ewfd_code_cache(void);
void free_ewfd_code_cache(void);

/*
TODO: 
load from conf file
*/
struct ewfd_padding_conf_t* demo_get_front_schedule_unit_conf(void);
struct ewfd_padding_conf_t* demo_get_front_padding_unit_conf(void);
void demo_free_front_conf(ewfd_client_conf_st *conf);

#endif // EWFD_CONF_H_
