#ifndef COMMON_H
#define COMMON_H

#include <ctype.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define COLOR_RED     "\033[38;2;255;0;0m"
#define COLOR_BLUE    "\033[38;2;0;0;255m"
#define COLOR_GREEN   "\033[38;2;0;255;0m"
#define COLOR_RESET   "\033[0m"

#define SUCCESS       0U
#define FAILURE       1U
#define NOT_SUPPORTED 2U
#define BAD_PARAMETER 3U

#define trace()                                                                        \
    do                                                                                 \
    {                                                                                  \
        printf("%sTRACE%s %s:%d\n", COLOR_GREEN, COLOR_RESET, __FUNCTION__, __LINE__); \
    }                                                                                  \
    while (0)

#define CHECK(x)                                                                                  \
    uint32_t retval = (x);                                                                        \
    if (retval != SUCCESS)                                                                        \
    {                                                                                             \
        printf("%s%s%s:%d '%s' : 0x%08X \n ", COLOR_RED, __FUNCTION__, COLOR_RESET, __LINE__, #x, \
               retval);                                                                           \
        goto exit;                                                                                \
    }

#define HEXDUMP(B, L)                                                         \
    ({                                                                        \
        uint32_t addr = 0x00000000U;                                          \
        printf("memory length : %u\n", L);                                    \
        printf("          0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F\n"); \
        printf("%08X ", addr);                                                \
        for (uint32_t i = 0U; i < L; i++)                                     \
        {                                                                     \
            printf("%02X ", B[i]);                                            \
            if ((i & (0x0FU)) == 0x0FU)                                       \
            {                                                                 \
                addr += 0x10U;                                                \
                if (addr < L)                                                 \
                {                                                             \
                    printf("\n%08X ", addr);                                  \
                }                                                             \
            }                                                                 \
        }                                                                     \
        printf("\n");                                                         \
    })

typedef struct {
    size_t dataLength;
    uint8_t data[4096U];
} OBJECT_DATA;

typedef enum {
    TYPE_KEY_PAIR,
    TYPE_PRIVATE_KEY,
    TYPE_PUBLIC_KEY,
} KEY_TYPE;

typedef enum {
    P192,
    P224,
    P256,
    P384,
    P521
} EC_CURVE;

size_t HexStr2Byte(char *hex, char *out);
BIGNUM *Bn2Hex(char *hex);

#endif /* COMMON_H */