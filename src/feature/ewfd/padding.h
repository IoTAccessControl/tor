#ifndef EWFD_PADDING_H_
#define EWFD_PADDING_H_

#include "core/or/or.h"
#include "trunnel/circpad_negotiation.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_EWFD_UNITS_ON_CIRC 5

/**
unit_idx: slot, 0, 1
unit_uuid: 脚本编号
*/
typedef struct ewfd_padding_conf_t {
	uint8_t unit_slot; // 通过指定slot来固定替换circ上已有的padding unit
	uint8_t unit_uuid;
	uint8_t deploy_hop; // bit3, [Exit][OR][Client]
	uint8_t target_hopnum;
	uint16_t code_len;
	uint8_t code[0];
} ewfd_padding_conf_st;

/** 将conf，脚本绑定到一个vm上
*/
typedef struct ewfd_padding_unit_t {
	uint8_t unit_version; // 区分同一个slot，同一uuid的padding unit
	bool peer_is_up;      // 确认peer是否已经启动
	struct ewfd_padding_conf_t *conf;
} ewfd_padding_unit_st;

/** TODO: 将circ的padding unit数组换成这个结构体，不和原来的padding machine共享machine_ctr等字段
*/
typedef struct ewfd_padding_context_t {
	ewfd_padding_unit_st *slots[MAX_EWFD_UNITS_ON_CIRC];
	uint8_t units_cnt;
} ewfd_padding_context_st;

// init ewfd padding framework
void ewfd_padding_init(void);
void ewfd_padding_free(void);


int ewfd_handle_padding_negotiate(circuit_t *circ, circpad_negotiate_t *negotiate);
int ewfd_handle_padding_negotiated(circuit_t *circ, circpad_negotiated_t *negotiated);

// dispatch padding commands
int add_ewfd_units_on_circ(circuit_t *circ);
void free_all_ewfd_units_on_circ(circuit_t *circ);

int trigger_ewfd_units_on_circ(circuit_t *circ, bool is_send, bool toward_origin);

// other events
// int on_add_ewfd_units_on_circ();
// int on_remove_ewfd_units_on_circ();

#endif