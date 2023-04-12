#ifndef EWFD_EBPF_RUNTIME_H_
#define EWFD_EBPF_RUNTIME_H_

typedef struct ewfd_padding_op {
	void (*ewfd_dummy_packet)(void *);
} ewfd_padding_op_st;

#endif