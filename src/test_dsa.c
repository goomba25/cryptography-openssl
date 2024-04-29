#include "test_dsa.h"

#include "test_hash.h"

uint32_t test_dsa_sha1_sign()
{
    uint32_t result = SUCCESS;

    // NIST vector
    uint8_t *P =
        "aa9a0d6116807cf74e0ee63cdc6f38110f873affc6db2d9ad854ae27a384230dd904f8a6ceb11bb2983973c0d8"
        "19ccf02df04d82cc7926d61be78f5ad92a05b9308aca5a9ecd7461fc1b51da3e9d849fce5075d9c027f1afeb0a"
        "b7916df4a7b72b3bb00461f43542313c8b82354f88c542a48bfa73bcc1db4ffed329b2cc5cff";  // Prime
    uint8_t *Q = "f780e706db7e465dd0eeec3f1b929240157f476f";                             // Subprime
    uint8_t *G =
        "3b80103191e0b2d6b949e1dbfb621c5c8fb45bb9f9db5a52372728045015b56975b56b3f8b97659600194442d0"
        "75a8c5c8c1588ee01d848e7b42905edda807209e1395a130cf7fb2630c2bfcf46cc2f8cdc2e0a11eed9189b35d"
        "92b2619daff95ac18b0c0e2fd1c8e449e225f812b29815efd1d05d7bc1bf6efaa1766ec2a322";  // Base
    uint8_t *X = "";                                                                     // Private
    uint8_t *Y =
        "4029a121f6627127bc8aeb97bfeec2a80b0800ed015a91bcf39869187535e91b5db53ee840056529c1e4ccdbc2"
        "1e64b813cc3d2c170c6030a0d195645bd3657256647bafc0623944e44f1c5f7c50318182e68966b9a16f46da9e"
        "343301db694d8f3b62052b66dae25222c53125a7893416994055a0284393f67c6b2e3bbf0cd4";  // Public

    uint8_t *MSG =
        "7b4b528be9e0353c0156dc685bf0517ef4cc0ab18cb96a614c4889d6ac26383494a840abc1a8ebef6b90c6e825"
        "b4a4aa04e5e6a70342fa23a65222e9de50773d2dc62d110a5e187c87f46f6731efd18a38d28597d00e06b4d61b"
        "bf2fb7c6136d8ecda0248ca9c5ca9dab614e484ade05d7bc6fe7b9c395fb24cae810ff3014ae";

    uint8_t hashDst[SHA_DIGEST_LENGTH] = {
        0U,
    };

    DSA *key         = NULL;
    DSA_SIG *sign    = NULL;

    BIGNUM *prime    = Bn2Hex(P);
    BIGNUM *subprime = Bn2Hex(Q);
    BIGNUM *base     = Bn2Hex(G);
    BIGNUM *private  = Bn2Hex(X);
    BIGNUM *public   = Bn2Hex(Y);
    BIGNUM *r        = NULL;
    BIGNUM *s        = NULL;

    trace();

    result = test_hash(MSG, strlen(MSG), hashDst, SHA_DIGEST_LENGTH);
    if (result != SUCCESS)
    {
        printf("failed to test_ecdh_P192\n");
        goto exit;
    }

    key  = ssl_CreateDSAKey(TYPE_PUBLIC_KEY, prime, subprime, base, private, public);

    sign = DSA_SIG_new();

    sign = DSA_do_sign(hashDst, SHA_DIGEST_LENGTH, key);
    DSA_SIG_get0(sign, &r, &s);

    printf("\n=================== R VALUE ===================\n");
    BN_print_fp(stdout, r);

    printf("\n=================== S VALUE ===================\n");
    BN_print_fp(stdout, s);
    printf("\n");

exit:
    return result;
}

uint32_t test_dsa_sha1_verify()
{
    uint32_t result = SUCCESS;

    // NIST vector
    uint8_t *P =
        "aa9a0d6116807cf74e0ee63cdc6f38110f873affc6db2d9ad854ae27a384230dd904f8a6ceb11bb2983973c0d8"
        "19ccf02df04d82cc7926d61be78f5ad92a05b9308aca5a9ecd7461fc1b51da3e9d849fce5075d9c027f1afeb0a"
        "b7916df4a7b72b3bb00461f43542313c8b82354f88c542a48bfa73bcc1db4ffed329b2cc5cff";  // Prime
    uint8_t *Q = "f780e706db7e465dd0eeec3f1b929240157f476f";                             // Subprime
    uint8_t *G =
        "3b80103191e0b2d6b949e1dbfb621c5c8fb45bb9f9db5a52372728045015b56975b56b3f8b97659600194442d0"
        "75a8c5c8c1588ee01d848e7b42905edda807209e1395a130cf7fb2630c2bfcf46cc2f8cdc2e0a11eed9189b35d"
        "92b2619daff95ac18b0c0e2fd1c8e449e225f812b29815efd1d05d7bc1bf6efaa1766ec2a322";  // Base
    uint8_t *X = "";                                                                     // Private
    uint8_t *Y =
        "4029a121f6627127bc8aeb97bfeec2a80b0800ed015a91bcf39869187535e91b5db53ee840056529c1e4ccdbc2"
        "1e64b813cc3d2c170c6030a0d195645bd3657256647bafc0623944e44f1c5f7c50318182e68966b9a16f46da9e"
        "343301db694d8f3b62052b66dae25222c53125a7893416994055a0284393f67c6b2e3bbf0cd4";  // Public

    uint8_t *MSG =
        "7b4b528be9e0353c0156dc685bf0517ef4cc0ab18cb96a614c4889d6ac26383494a840abc1a8ebef6b90c6e825"
        "b4a4aa04e5e6a70342fa23a65222e9de50773d2dc62d110a5e187c87f46f6731efd18a38d28597d00e06b4d61b"
        "bf2fb7c6136d8ecda0248ca9c5ca9dab614e484ade05d7bc6fe7b9c395fb24cae810ff3014ae";

    uint8_t *R          = "6834f49ea079dd8bb89ce0f9698039a734ce286f";
    uint8_t *S          = "146eee21b375df3812ddc7f7ce81908e571cbf8a";

    uint8_t temp[4096U] = {
        0U,
    };

    uint8_t hashDst[SHA_DIGEST_LENGTH] = {
        0U,
    };

    DSA *key         = NULL;
    DSA_SIG *sign    = NULL;

    BIGNUM *prime    = Bn2Hex(P);
    BIGNUM *subprime = Bn2Hex(Q);
    BIGNUM *base     = Bn2Hex(G);
    BIGNUM *private  = Bn2Hex(X);
    BIGNUM *public   = Bn2Hex(Y);
    BIGNUM *r        = Bn2Hex(R);
    BIGNUM *s        = Bn2Hex(S);
    OBJECT_DATA msg  = {
        0U,
    };

    trace();

    msg.dataLength = HexStr2Byte(MSG, (char *)temp);
    (void)memcpy(msg.data, temp, msg.dataLength);
    (void)memset(temp, 0, 4096U);

    result = test_hash(msg.data, msg.dataLength, hashDst, SHA_DIGEST_LENGTH);
    if (result != SUCCESS)
    {
        printf("failed to test_ecdh_P192\n");
        goto exit;
    }

    key  = ssl_CreateDSAKey(TYPE_PRIVATE_KEY, prime, subprime, base, private, public);

    sign = DSA_SIG_new();
    DSA_SIG_set0(sign, r, s);

    if (DSA_do_verify(hashDst, SHA_DIGEST_LENGTH, sign, key) > 0)
    {
        printf("OK, Verified.\n");
    }
    else
    {
        printf("Failed.\n");
    }

exit:
    return result;
}