#include "common.h"

size_t HexStr2Byte(char *hex, char *out)
{
    size_t outLength = -1;
    size_t hexStr_sz = 0;
    size_t index     = 0;
    char c;
    char val = 0;

    if (!hex || !out)
    {
        return outLength;
    }
    hexStr_sz = strlen(hex);
    outLength = hexStr_sz / 2;
    if (hexStr_sz % 2 == 1)
    {
        index++;
        outLength++;
    }
    for (size_t i = 0; i < hexStr_sz; i++)
    {
        c   = hex[i];
        val = 0;
        if (c >= '0' && c <= '9')
        {
            val = (c - '0');
        }
        else if (c >= 'A' && c <= 'F')
        {
            val = (10 + (c - 'A'));
        }
        else if (c >= 'a' && c <= 'f')
        {
            val = (10 + (c - 'a'));
        }
        else
        {
            outLength = -1;
            break;
        }

        out[(index / 2)] += val << (((index + 1) % 2) * 4);
        index++;
    }

    return outLength;
}

BIGNUM *Bn2Hex(char *hex)
{
    uint32_t result     = SUCCESS;
    uint8_t data[4096U] = {
        0U,
    };
    uint32_t dataLen = 0U;
    BIGNUM *out      = NULL;

    if (hex == NULL)
    {
        result = BAD_PARAMETER;
        goto exit;
    }

    dataLen = HexStr2Byte(hex, (char *)data);

    out     = BN_bin2bn(data, dataLen, NULL);

exit:
    return out;
}