#ifndef EWFD_PADDING_H_
#define EWFD_PADDING_H_

#include "core/or/or.h"


typedef struct ewfd_padding_conf_t {
	uint8_t unit_idx;
	uint16_t code_len;
	uint8_t code[0];
} ewfd_padding_conf_st;

typedef struct ewfd_padding_unit_t {
	uint8_t unit_idx;
	struct ewfd_padding_conf_t *conf;
} ewfd_padding_unit_st;

// init ewfd padding framework
void ewfd_padding_init(void);
void ewfd_padding_free(void);


int ewfd_handle_padding_negotiate();

// dispatch padding commands
int add_ewfd_units_on_circ(circuit_t *circ);
// int on_add_ewfd_units_on_circ();

int remove_ewfd_units_on_circ(circuit_t *circ);
// int on_remove_ewfd_units_on_circ();

int trigger_ewfd_units_on_circ(circuit_t *circ);

#endif