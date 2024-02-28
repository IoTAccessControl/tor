#include "toml.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_MODES 5
#define MAX_DEFNSE 10

struct defense_conf {
	char name[32];
	int def_type;
	int arg1;
	int arg2;
	int arg3;
};

struct mode_conf {
	int mode_type;
	int defense_list[MAX_DEFNSE];
};

struct settings {
	int mode_idx;
	struct mode_conf modes[MAX_MODES];
	struct defense_conf defenses[MAX_DEFNSE];
};

int main() {
	printf("read tor defense conf\n");
	const char conf[] = "defense.toml";

	FILE *fp = fopen(conf, "r");
	if (fp == NULL) {
		fprintf(stderr, "ERROR: cannot open file: %s\n", conf);
		exit(1);
	}

	char errbuf[200];
	toml_table_t *tbl = toml_parse_file(fp, errbuf, sizeof(errbuf));
	if (!tbl) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	// get modes
	toml_array_t *arr = toml_table_array(tbl, "modes");

	return 0;
}