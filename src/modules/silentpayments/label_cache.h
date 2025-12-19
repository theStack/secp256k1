#ifndef SECP256K1_MODULE_SILENTPAYMENTS_LABEL_CACHE_H
#define SECP256K1_MODULE_SILENTPAYMENTS_LABEL_CACHE_H

/* Silent Payments "label cache" implementation using a simple hash map,
 * based on khash [https://github.com/attractivechaos/klib/blob/master/khash.h]
 * and rapidhash [https://github.com/Nicoshev/rapidhash/blob/master/rapidhash.h] */

/* the "inline" keyword is not supported in C89, so disable it for khash and rapidhash */
#define kh_inline
#include "../../khash.h"
#define RAPIDHASH_INLINE
#include "../../rapidhash.h"
typedef struct { uint8_t data[33]; } label_cache_key_t;
typedef struct { uint8_t data[32]; } label_cache_value_t;
static khint_t hash_label_cache_key(label_cache_key_t k) { return rapidhash(k.data, sizeof(k.data)); }
static int label_cache_key_equal(label_cache_key_t a, label_cache_key_t b) { return secp256k1_memcmp_var(a.data, b.data, 32) == 0; }
KHASH_INIT(label_cache_hashmap, label_cache_key_t, label_cache_value_t, 1, hash_label_cache_key, label_cache_key_equal)

typedef khash_t(label_cache_hashmap) label_cache_t;

static label_cache_t* label_cache_init(void) {
    return kh_init(label_cache_hashmap);
}

static void label_cache_destroy(label_cache_t *h) {
    kh_destroy(label_cache_hashmap, h);
}

static int label_cache_put(label_cache_t *h, const unsigned char *label33, const unsigned char *label_tweak32) {
    label_cache_key_t k;
    label_cache_value_t v;
    khint_t it;
    int ret;
    memcpy(k.data, label33, 33);
    memcpy(v.data, label_tweak32, 32);
    it = kh_put(label_cache_hashmap, h, k, &ret);
    kh_value(h, it) = v;
    return ret;
}

static unsigned char* label_cache_get(label_cache_t *h, const unsigned char *label33) {
    label_cache_key_t k;
    khint_t it;
    memcpy(k.data, label33, 33);
    it = kh_get(label_cache_hashmap, h, k);
    if (it != kh_end(h)) {
        label_cache_value_t *v = &kh_value(h, it);
        return &v->data[0];
    }
    return NULL;
}

static size_t label_cache_size(label_cache_t *h) {
    return kh_size(h);
}

static const unsigned char* label_cache_lookup_fun(const unsigned char *key, const void *cache_ptr) {
    return label_cache_get((label_cache_t *)cache_ptr, key);
}

#endif
