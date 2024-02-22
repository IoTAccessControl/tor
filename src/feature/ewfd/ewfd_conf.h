#ifndef EWFD_CONF_H_
#define EWFD_CONF_H_

#include <stdbool.h>
#include "lib/smartlist_core/smartlist_core.h"

#define EWFD_EVENT_QUEUE_TICK_MS 50 // 20ms，调用一次全局事件队列
#define MAX_EWFD_TICK_GAP_MS 500 // 500ms, queue最多调度500ms内的event，之前的event过期丢弃
#define MAX_EVENT_IN_QUEUE 2000 // 2000个event，超过丢弃

// padding/schedule unit默认tick间隔
#define DEFAULT_EWFD_PADDING_GAP_MS 200 // 50ms, 
#define DEFAULT_EWFD_SCHEDULE_GAP_MS 500 // 500ms

enum MyPaddingType {
	EWFD_PADDING_NONE = 0,
	EWFD_PADDING_APE = 1,
	EWFD_PADDING_EBPF_TEST = 2,
	EWFD_PADDING_TARMORT = 3,
	EWFD_PADDING_INTERSPACE = 4,
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
