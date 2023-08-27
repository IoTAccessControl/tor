#ifndef ewfd_unit_H_
#define ewfd_unit_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum EWFD_CODE_TYPE {
	EWFD_CODE_TYPE_INIT, // init maps
	EWFD_CODE_TYPE_MAIN, // run tick/schedule
};

#define MAX_EBPF_CODE 2048

/*
TODO: code cache
*/
typedef struct ewfd_code_t {
	int code_type;
	int code_len;
	char name[32];
	uint64_t code[MAX_EBPF_CODE];
} ewfd_code_st;

struct ewfd_unit_t;
struct ewfd_padding_conf_t;

struct ewfd_unit_t *init_ewfd_unit(struct ewfd_padding_conf_t *conf);
// bool ewfd_unit_set_code(ewfd_code_st *ewfd_code);
void free_ewfd_unit(struct ewfd_unit_t *ewfd_unit);
uint64_t run_ewfd_unit(struct ewfd_unit_t *ewfd_unit, void *ewfd_ctx, size_t len);

#endif // ewfd_unit_H_
