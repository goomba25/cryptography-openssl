/* Create Keys */

#ifndef KEYS_H
#define KEYS_H

#include "common.h"
EC_KEY *ssl_CreateECKey(KEY_TYPE type, EC_CURVE curve, BIGNUM *qx, BIGNUM *qy, BIGNUM *d);
DSA *ssl_CreateDSAKey(KEY_TYPE type, BIGNUM *p, BIGNUM *q, BIGNUM *g, BIGNUM *x, BIGNUM *y);

#endif /* KEYS_H */