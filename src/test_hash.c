#include "test_hash.h"

uint32_t test_hash(uint8_t *msg, uint32_t msgLen, uint8_t *dst, uint32_t dstLen)
{
    uint32_t result = SUCCESS;
    uint8_t temp[dstLen];

    trace();
    switch (dstLen)
    {
    case SHA_DIGEST_LENGTH:
        if (!SHA1(msg, msgLen, temp))
        {
            result = FAILURE;
        }
        break;
    case SHA224_DIGEST_LENGTH:
        if (!SHA224(msg, msgLen, temp))
        {
            result = FAILURE;
        }
        break;
    case SHA256_DIGEST_LENGTH:
        if (!SHA256(msg, msgLen, temp))
        {
            result = FAILURE;
        }
        break;
    case SHA384_DIGEST_LENGTH:
        if (!SHA384(msg, msgLen, temp))
        {
            result = FAILURE;
        }
        break;
    case SHA512_DIGEST_LENGTH:
        if (!SHA512(msg, msgLen, temp))
        {
            result = FAILURE;
        }
        break;
    default:
        result = NOT_SUPPORTED;
        break;
    }
    CHECK(result);

    HEXDUMP(temp, dstLen);

    (void)memcpy(dst, temp, dstLen);

exit:
    return result;
}