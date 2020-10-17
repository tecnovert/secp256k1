/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSAOTVES_TESTS
#define SECP256K1_MODULE_ECDSAOTVES_TESTS

#include "include/secp256k1_ecdsaotves.h"

void test_ecdsaotves(void) {
    secp256k1_scalar s;
    random_scalar_order(&s);

}

void run_ecdsaotves_tests(void) {
    int i;
    printf("Running ECDSA OT-VES tests.\n");

    for (i = 0; i < count; i++) {
        test_ecdsaotves();
    }
}

#endif
