#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tlv.h"
#include "processor.h"
#include "safe_storage.h"

typedef struct {
    char* key;
    uint8_t* value;
    size_t value_len;
} item_t;

typedef struct {
    char key[0x20];
} crypt_key_t;

struct storage_t {
    crypt_key_t* mk;
    item_t* items;
    size_t num_items;
    size_t capacity;
};

storage_t* global_storage;

crypt_key_t* create_random_key() {
    crypt_key_t* key = calloc(sizeof(crypt_key_t), 1);
    FILE* random = fopen("/dev/urandom", "rb");
    fread(&key->key, sizeof(key->key), 1, random);
    fclose(random);
    return key;
}

void encrypt_data(crypt_key_t* key, uint8_t* data, size_t data_len) {
    for (int i = 0; i < data_len; ++i) {
        data[i] = key->key[i % sizeof(key->key)] ^ ((uint8_t*)data)[i];
    }
}

void decrypt_data(crypt_key_t* key, uint8_t* enc_data, size_t data_len) {
    encrypt_data(key, enc_data, data_len);
}

storage_t* create_storage() {
    storage_t* storage = calloc(sizeof(storage_t), 1);
    storage->capacity = 8;
    storage->num_items = 0;
    storage->mk = create_random_key();
    storage->items = calloc(sizeof(item_t), storage->capacity);
    return storage;
}


void add_item(storage_t* storage, char* key, uint8_t* value, size_t value_len) {
    // if item exists, update it's value
    if (storage->capacity == storage->num_items) {
        storage->capacity *= 2;
        storage->items = realloc(storage->items, sizeof(item_t) * storage->capacity);
    }
    item_t* new_item = &storage->items[storage->num_items++];
    new_item->key = strdup(key);
    new_item->value = calloc(value_len, 1);
    memcpy(new_item->value, value, value_len);
    // account for null byte
    new_item->value_len = value_len;
    // encrypt value
    encrypt_data(storage->mk, (uint8_t*)new_item->value, new_item->value_len);
}


uint8_t* get_item(storage_t* storage, char* key, size_t* len) {
    uint8_t* res = NULL;
    for (size_t i = 0; i < storage->num_items; ++i) {
        item_t* item = &storage->items[i];
        if (!strcmp(key, item->key)) {
            decrypt_data(storage->mk, (uint8_t*)item->value, item->value_len);
            res = calloc(item->value_len, 1);
            memcpy(res, item->value, item->value_len);
            *len = item->value_len;
            encrypt_data(storage->mk, (uint8_t*)item->value, item->value_len);
            break;
        }
    }
    return res;
}

void storage_init() {
    global_storage = create_storage();
}

int process_storage_request(uint64_t id, char* cmd, uint8_t** prequest, size_t* remaining_size) {
    if (id >= MAX_RESULTS) {
        return 1;
    }
    result_t* res = &results[id];
    if (!strcmp(cmd, "load")) {
        object_t* key = parse_object(prequest, remaining_size);
        if (key == NULL || key->type != STRING) { return 1; }
        
        size_t len;
        uint8_t* value = get_item(global_storage, GET_STRING(key), &len);
        if (value == NULL) {
            res->error_code = FAILURE;
            res->length = 0;
        } else {
            res->error_code = SUCCESS;
            res->length = len;
            memcpy(res->result_data, value, sizeof(res->result_data));
        }
    } else if (!strcmp(cmd, "store")) {
        object_t* key = parse_object(prequest, remaining_size);
        if (key == NULL || key->type != STRING) { return 1; }

        object_t* value = parse_object(prequest, remaining_size);
        if (value == NULL || value->type != BYTES) { return 1; }

        add_item(global_storage, GET_STRING(key), GET_BYTES(value), GET_LENGTH(value));
        res->error_code = SUCCESS;
    } else {
        return 1;
    }
    return 0;
}