#ifndef _EWFD_HELPER_H_
#define _EWFD_HELPER_H_

struct ebpf_vm;

void ewfd_register_datastream_helpers(struct ebpf_vm *vm);

void ewfd_register_histrogram_helpers(struct ebpf_vm *vm);

// test algorithims here
void ewfd_register_tor_test_helpers(struct ebpf_vm *vm);

#endif // _EWFD_HELPER_H_
