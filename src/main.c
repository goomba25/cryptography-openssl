#include "common.h"
#include "test_dsa.h"
#include "test_ecdh.h"
#include "test_hash.h"

#define MSG                                                                                        \
    "802cdf5437fad976e011a42bc1aa5ea694ae2326e4848c70ba26757d797b047007e1e7cb2d08dce14107778f02a9" \
    "2027c3085badcc5e4c46fd177aedb42bd368f1aaf07ab8999b5bb7fc8e6529347e10fa8b58202c0ecb1d799b0604" \
    "3a3ac33c87b084cba0521cca8b187216fff28249815fa4e9cd3b11df77d8a32ad251dcd4"

int main()
{
    uint32_t result                    = SUCCESS;

    uint8_t hashDst[SHA_DIGEST_LENGTH] = {
        0U,
    };

    OPENSSL_init();
    OpenSSL_add_all_algorithms();

    result = test_hash(MSG, strlen(MSG), hashDst, SHA_DIGEST_LENGTH);
    if (result != SUCCESS)
    {
        printf("failed to test_hash\n");
        goto exit;
    }

    result = test_ecdh_P192();
    if (result != SUCCESS)
    {
        printf("failed to test_ecdh_P192\n");
    }

    result = test_dsa_sha1_sign();
    if (result != SUCCESS)
    {
        printf("failed to test_dsa_sha1_sign\n");
    }

    result = test_dsa_sha1_verify();
    if (result != SUCCESS)
    {
        printf("failed to test_dsa_sha1_verify\n");
    }

exit:
    return 0;
}