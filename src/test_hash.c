#include "test_hash.h"

uint32_t test_hash(uint8_t *msg, uint32_t msgLen, uint8_t *dst, uint32_t dstLen)
{
    uint32_t result = SUCCESS;
    uint8_t *output = NULL;

    output          = malloc(dstLen);

    switch (dstLen)
    {
    case SHA_DIGEST_LENGTH:
        if (!SHA1(msg, msgLen, output))
        {
            result = FAILURE;
        }
        break;
    case SHA224_DIGEST_LENGTH:
        if (!SHA224(msg, msgLen, output))
        {
            result = FAILURE;
        }
        break;
    case SHA256_DIGEST_LENGTH:
        if (!SHA256(msg, msgLen, output))
        {
            result = FAILURE;
        }
        break;
    case SHA384_DIGEST_LENGTH:
        if (!SHA384(msg, msgLen, output))
        {
            result = FAILURE;
        }
        break;
    case SHA512_DIGEST_LENGTH:
        if (!SHA512(msg, msgLen, output))
        {
            result = FAILURE;
        }
        break;
    default:
        result = NOT_SUPPORTED;
        break;
    }
    if (result == FAILURE)
    {
        printf("hash error\n");
        printf("=============================================\n");
        goto exit;
    }

    if (result == NOT_SUPPORTED)
    {
        printf("Not supported algorithm\n");
        printf("=============================================\n");
        goto exit;
    }

    printf("OK, hash\n");
    BN_print_fp(stdout, BN_bin2bn(output, dstLen, NULL));
    printf("\n=============================================\n");

    (void)memcpy(dst, output, dstLen);

exit:
    if (output != NULL)
    {
        free(output);
    }

    return result;
}
