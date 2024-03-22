
all: test1 parse

test1: test1.c
	$(CC) -o $@.exe $< toml.c

parse: parse_conf.c
	$(CC) -o $@.exe $< toml.c
	./parse.exe

clean:
	rm -f test1 parse