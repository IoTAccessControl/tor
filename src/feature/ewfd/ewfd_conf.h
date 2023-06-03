#ifndef EWFD_CONF_H_
#define EWFD_CONF_H_

#include <stdbool.h>
#include "lib/smartlist_core/smartlist_core.h"

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

#endif // EWFD_CONF_H_
