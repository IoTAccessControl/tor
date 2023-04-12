#ifndef EWFD_EBPF_RUNTIME_H_
#define EWFD_EBPF_RUNTIME_H_

#include "feature/ewfd/circuit_padding.h"

void run_ewfd_padding_vm(ewfd_padding_runtime_st *ewfd_rt);
void run_ewfd_schedule_vm(ewfd_padding_runtime_st *ewfd_rt);

#endif
