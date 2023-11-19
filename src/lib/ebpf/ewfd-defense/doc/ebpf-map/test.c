#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 1000

typedef struct {
    char* key;
    char* value;
} Entry;

typedef struct {
    Entry* entries[SIZE];
} HashMap;

unsigned int hash(const char* key) {
    unsigned int hash = 0;
    int i;
    for (i = 0; i < strlen(key); i++) {
        hash = (hash * 31) + key[i];
    }
    return hash % SIZE;
}

HashMap* createHashMap() {
    HashMap* hashmap = (HashMap*)malloc(sizeof(HashMap));
    int i;
    for (i = 0; i < SIZE; i++) {
        hashmap->entries[i] = NULL;
    }
    return hashmap;
}

void put(HashMap* hashmap, const char* key, const char* value) {
    unsigned int index = hash(key);
    Entry* entry = (Entry*)malloc(sizeof(Entry));
    entry->key = strdup(key);
    entry->value = strdup(value);
    hashmap->entries[index] = entry;
}

char* get(HashMap* hashmap, const char* key) {
    unsigned int index = hash(key);
    Entry* entry = hashmap->entries[index];
    if (entry != NULL && strcmp(entry->key, key) == 0) {
        return entry->value;
    }
    return NULL;
}

void removeEntry(HashMap* hashmap, const char* key) {
    unsigned int index = hash(key);
    Entry* entry = hashmap->entries[index];
    if (entry != NULL && strcmp(entry->key, key) == 0) {
        free(entry->key);
        free(entry->value);
        free(entry);
        hashmap->entries[index] = NULL;
    }
}

int containsKey(HashMap* hashmap, const char* key) {
    unsigned int index = hash(key);
    Entry* entry = hashmap->entries[index];
    if (entry != NULL && strcmp(entry->key, key) == 0) {
        return 1;
    }
    return 0;
}

void destroyHashMap(HashMap* hashmap) {
    int i;
    for (i = 0; i < SIZE; i++) {
        Entry* entry = hashmap->entries[i];
        if (entry != NULL) {
            free(entry->key);
            free(entry->value);
            free(entry);
        }
    }
    free(hashmap);
}

int main() {
    HashMap* myMap = createHashMap();
    put(myMap, "key1", "value1");
    put(myMap, "key2", "value2");

    char* value = get(myMap, "key1");
    if (value != NULL) {
        printf("Value for key1: %s\n", value);
    }

    if (containsKey(myMap, "key2")) {
        printf("Key2 exists\n");
    }

    removeEntry(myMap, "key1");

    value = get(myMap, "key1");
    if (value == NULL) {
        printf("Key1 does not exist\n");
    }

    destroyHashMap(myMap);

    return 0;
}