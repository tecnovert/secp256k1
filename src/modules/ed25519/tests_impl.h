/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ED25519_TESTS
#define SECP256K1_MODULE_ED25519_TESTS

#include "include/secp256k1_ed25519.h"

void run_ed25519_tests(void) {
    int rv;
    unsigned char k1[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
    };
    unsigned char k2[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00,
    };
    unsigned char r[32], K1[32], K2[32];

    CHECK(crypto_core_ed25519_bytes() == 32);


    memset(r, 0, 32);

    crypto_core_ed25519_scalar_add(r, k1, k2);
    CHECK(memcmp(r, k2, 32) > 0);

    crypto_core_ed25519_scalar_sub(r, r, k2);
    CHECK(memcmp(r, k1, 32) == 0);

    rv = crypto_scalarmult_ed25519_base_noclamp(K1, k1);
    CHECK(rv == 0);

    rv = crypto_scalarmult_ed25519_base(K2, k2);
    CHECK(rv == 0);

    rv = crypto_core_ed25519_add(r, K1, K2);
    CHECK(rv == 0);

    rv = crypto_core_ed25519_sub(r, r, K2);
    CHECK(rv == 0);
    CHECK(memcmp(r, K1, 32) == 0);
}

#endif
