#include "toml.h"
#include <stdio.h>
#include <stdlib.h>

char doc[] = "\n"
	"ints  = [1, 2, 3]\n"
	"mixed = [1, 'one', 1.2]\n"
	"\n"
	"[[aot]]\n"
	"k = 'one'\n"
	"[[aot]]\n"
	"k = 'two'\n";

int main() {
	char errbuf[200];
	toml_table_t *tbl = toml_parse(doc, errbuf, sizeof(errbuf));
	if (!tbl) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	// Array of ints.
	toml_array_t *arr = toml_table_array(tbl, "ints");
	int l = toml_array_len(arr);
	printf("ints:\n");
	for (int i = 0; i < l; i++)
		printf("  index %d = %ld\n", i, toml_array_int(arr, i).u.i);
	printf("\n");
	
	// mixed array
	arr = toml_table_array(tbl, "mixed");
	l = toml_array_len(arr);
	printf("mixed:\n");
	for (int i = 0; i < l; i++) {
		toml_value_t val = toml_array_int(arr, i);
		if (val.ok) {
			printf("  index %d = %ld\n", i, val.u.i);
			continue;
		}
		val = toml_array_double(arr, i);
		if (val.ok) {
			printf("  index %d = (float)%0.17g\n", i, val.u.d);
			continue;
		}
		val = toml_array_string(arr, i);
		if (val.ok) {
			printf("  index %d = \"%s\"\n", i, val.u.s);
			continue;
		}
	}
	printf("\n");

	// aot
	arr = toml_table_array(tbl, "aot");
	l = toml_array_len(arr);
	for (int i = 0; i < l; i++) {
		toml_table_t *t = toml_array_table(arr, i);
		toml_value_t val = toml_table_string(t, "k");
		if (val.ok)
			printf("  aot[%d].k = \"%s\"\n", i, val.u.s);
	}

	return 0;
}