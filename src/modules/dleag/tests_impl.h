/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_DLEAG_TESTS
#define SECP256K1_MODULE_DLEAG_TESTS

#include "include/secp256k1_dleag.h"

void test_dleag(void) {
    size_t bits = 252;
    unsigned char key[32], nonce[32];
    unsigned char proof[65 + 128 + 64 + 193 * 252];
    size_t proof_len = 65 + 128 + 64 + 193 * 252;
    size_t i;

    secp256k1_testrand256(nonce);
    for (i = 0; i < 1000; ++i) {
        secp256k1_testrand256(key);
        key[0] &= 0x1f; /* Clear top 3 bits */
        if (ed25519_less_than_l_be(key)) {
            break;
        }
    }
    CHECK(ed25519_less_than_l_be(key));


    CHECK(secp256k1_dleag_prove(ctx, proof, &proof_len, key, bits, nonce,
        &secp256k1_generator_const_g, &secp256k1_generator_const_h,
        ed25519_gen, ed25519_gen2));

    CHECK(secp256k1_dleag_verify(ctx, proof, proof_len,
        &secp256k1_generator_const_g, &secp256k1_generator_const_h,
        ed25519_gen, ed25519_gen2));

    CHECK(secp256k1_dleag_verify_ed25519_point(ctx, ed25519_gen));
}

void run_dleag_tests(void) {
    int i;
    printf("Running DLEAG tests.\n");

    for (i = 0; i < count; i++) {
        test_dleag();
    }
}

#endif
