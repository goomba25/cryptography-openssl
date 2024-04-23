/* Create Keys */

#ifndef KEYS_H
#define KEYS_H

#include "common.h"
EC_KEY *ssl_CreateECKey(KEY_TYPE type, EC_CURVE curve, BIGNUM *qx, BIGNUM *qy, BIGNUM *d);
uint32_t ssl_CreateDSAKey();

#endif /* KEYS_H */