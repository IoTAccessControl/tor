
define PRINT_HELP_PYSCRIPT
import re, sys

print("%-20s %s" % ("#Command", "#Describe"))
for line in sys.stdin:
	match = re.match(r'^([a-zA-Z\d_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

.PHONY: help build run clean 

help:
	@python3 -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

build: ## build the eBPF library and all test programs
	@echo "Building eBPF library"
	cmake -S . -B build
	cmake --build build


bpf:
	cd ewfd-defense && bash build.sh
	mv ewfd-defense/ebpf_code.h ewfd-defense/src/front_code.h

run: bpf build ## run the test program
	./build/bin/test

clean: ## clean the build directory
	rm -rf build