#ifndef _EWFD_TEST_H_
#define _EWFD_TEST_H_

#include <stddef.h>
#include <stdlib.h>


struct ewfd_unit_t;
struct ebpf_vm;

// test front 
int ewfd_init_front_unit(struct ewfd_unit_t *unit, void *status, size_t status_len);
int ewfd_run_front_unit(struct ewfd_unit_t *unit, void *status, size_t status_len);

// load front default code

#endif /* _EWFD_TEST_H_ */
