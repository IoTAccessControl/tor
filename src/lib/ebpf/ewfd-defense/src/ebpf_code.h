#ifndef EBPF_CODE_H_
#define EBPF_CODE_H_

// original code from libebpf repo
const unsigned char bpf_add_mem_64_bit_minimal[] = ""
"\x61\x12\x00\x00\x00\x00\x00\x00"
"\x61\x10\x04\x00\x00\x00\x00\x00"
"\x0f\x20\x00\x00\x00\x00\x00\x00"
"\x95\x00\x00\x00\x00\x00\x00\x00"
"";

const unsigned char ewfd_default_defense[] = ""
"\x61\x10\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00"
"";

#endif // EBPF_CODE_H_