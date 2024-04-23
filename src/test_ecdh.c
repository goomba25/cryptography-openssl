#include "test_ecdh.h"

uint32_t test_ecdh_P192()
{
    uint32_t result = SUCCESS;

    // NIST vector
    uint8_t* QCAVSx       = "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0";
    uint8_t* QCAVSy       = "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523";
    uint8_t* dIUT         = "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527";
    uint8_t* QIUTx        = "b15053401f57285637ec324c1cd2139e3a67de3739234b37";
    uint8_t* QIUTy        = "f269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6";
    uint8_t* ZIUT         = "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0";

    EC_KEY* privKey       = NULL;
    EC_KEY* pubKey        = NULL;

    uint8_t* secretKey    = NULL;
    uint32_t secretLength = 0U;

    BIGNUM* priv_qx       = Bn2Hex(QIUTx);
    BIGNUM* priv_qy       = Bn2Hex(QIUTy);
    BIGNUM* priv_d        = Bn2Hex(dIUT);

    BIGNUM* pub_qx        = Bn2Hex(QCAVSx);
    BIGNUM* pub_qy        = Bn2Hex(QCAVSy);

    trace();

    privKey      = ssl_CreateECKey(TYPE_PRIVATE_KEY, P192, priv_qx, priv_qy, priv_d);
    pubKey       = ssl_CreateECKey(TYPE_PUBLIC_KEY, P192, pub_qx, pub_qy, NULL);

    secretLength = (EC_GROUP_get_degree(EC_KEY_get0_group(privKey)) + 7) / 8;
    secretKey    = OPENSSL_malloc(secretLength);

    secretLength =
        ECDH_compute_key(secretKey, secretLength, EC_KEY_get0_public_key(pubKey), privKey, NULL);

    printf("=================== SECRET KEY ===================\n");
    HEXDUMP(secretKey, secretLength);

exit:
    return result;
}