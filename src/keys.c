#include "keys.h"

EC_KEY *ssl_CreateECKey(KEY_TYPE type, EC_CURVE curve, BIGNUM *qx, BIGNUM *qy, BIGNUM *d)
{
    uint32_t result    = SUCCESS;
    EC_KEY *key        = NULL;
    EC_GROUP *ecGroup  = NULL;
    EC_POINT *ecPoint  = NULL;

    int nid            = 0;

    uint8_t *keyBuffer = NULL;
    uint32_t keyLength = 0U;

    trace();

    switch (curve)
    {
    case P192:
        nid = EC_curve_nist2nid("P-192");
        break;
    case P224:
        nid = EC_curve_nist2nid("P-224");
        break;
    case P256:
        nid = EC_curve_nist2nid("P-256");
        break;
    case P384:
        nid = EC_curve_nist2nid("P-384");
        break;
    case P521:
        nid = EC_curve_nist2nid("P-521");
        break;
    default:
        result = NOT_SUPPORTED;
        break;
    }
    CHECK(result);

    key     = EC_KEY_new();
    ecGroup = EC_GROUP_new_by_curve_name(nid);

    if (!(EC_KEY_set_group(key, ecGroup) > 0))
    {
        printf("set group error\n");
        result = FAILURE;
        goto exit;
    }
    if (!(EC_KEY_generate_key(key) > 0))
    {
        printf("set key error\n");
        result = FAILURE;
        goto exit;
    }

    if (type == TYPE_PUBLIC_KEY)
    {
        ecPoint = EC_POINT_new(ecGroup);
        if (!EC_POINT_set_affine_coordinates(ecGroup, ecPoint, qx, qy, NULL))
        {
            printf("set qx, qy error\n");
            result = FAILURE;
            goto exit;
        }

        if (!EC_KEY_set_public_key(key, ecPoint))
        {
            printf("set public key error\n");
            result = FAILURE;
            goto exit;
        }

        keyLength = i2d_EC_PUBKEY(key, &keyBuffer);
        printf("=================== PUBLIC KEY ===================\n");
        HEXDUMP(keyBuffer, keyLength);
    }
    else
    {
        if (!EC_KEY_set_private_key(key, d))
        {
            printf("set private error\n");
            result = FAILURE;
            goto exit;
        }

        if (!EC_KEY_set_public_key_affine_coordinates(key, qx, qy))
        {
            printf("set qx, qy error\n");
            result = FAILURE;
            goto exit;
        }

        keyLength = i2d_ECPrivateKey(key, &keyBuffer);
        printf("=================== PRIVATE KEY ===================\n");
        HEXDUMP(keyBuffer, keyLength);
    }

exit:
    // if (result != SUCCESS)
    // {
    //     if (key != NULL)
    //     {
    //         EC_KEY_free(key);
    //     }
    // }
    if (keyBuffer != NULL)
    {
        free(keyBuffer);
    }
    if (ecGroup != NULL)
    {
        EC_GROUP_free(ecGroup);
    }
    if (ecPoint != NULL)
    {
        EC_POINT_free(ecPoint);
    }

    return key;
}

uint32_t ssl_CreateDSAKey()
{
    uint32_t result = SUCCESS;

exit:
    return result;
}