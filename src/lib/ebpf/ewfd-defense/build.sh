
python3 tools/compile_code.py -s bpf/front/front-1.ebpf.c -f src/front_code.h
python3 tools/compile_code.py -s bpf/wpf-pad/wpfpad.ebpf.c -f src/wpfpad_code.h


python3 tools/compile_code.py -s bpf/test/test_hash.bpf.c -f bpf/test/test_hash.h