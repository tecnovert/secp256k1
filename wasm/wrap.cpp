// Copyright (c) 2020 tecnovert
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <secp256k1.h>
#include <secp256k1_ed25519.h>
#include <secp256k1_dleag.h>
#include <stdint.h>

class CryptoLib
{
public:
    void initialise()
    {
        m_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    void finalise()
    {
        secp256k1_context_destroy(m_ctx);
    }

    int GetPubKey(uintptr_t result_hack, uintptr_t key_hack) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<unsigned char*>(key_hack);

        secp256k1_pubkey pubkey;
        size_t clen = 33;
        int ret = secp256k1_ec_pubkey_create(m_ctx, &pubkey, key);
        if (ret != 1) {
            return 1;
        }
        secp256k1_ec_pubkey_serialize(m_ctx, result, &clen, &pubkey, SECP256K1_EC_COMPRESSED);
        return 0;
    }

    int ed25519_scm_base(uintptr_t result_hack, uintptr_t key_hack) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<unsigned char*>(key_hack);
        return crypto_scalarmult_ed25519_base_noclamp(result, key);
    }

    int dleag_size(int num_bits)
    {
        return secp256k1_dleag_size(num_bits);
    }

    int dleag_prove(uintptr_t result_hack, uintptr_t key_hack, uintptr_t nonce_hack, int num_bits) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<unsigned char*>(key_hack);
        const unsigned char *nonce = reinterpret_cast<unsigned char*>(nonce_hack);

        size_t proof_len = secp256k1_dleag_size(num_bits);
        return secp256k1_dleag_prove(
            m_ctx,
            result,
            &proof_len,
            key,
            num_bits,
            nonce,
            &secp256k1_generator_const_g,
            &secp256k1_generator_const_h,
            ed25519_gen,
            ed25519_gen2);
    }

    int dleag_verify(uintptr_t proof_hack, int proof_length) const
    {
        unsigned char *proof = reinterpret_cast<unsigned char*>(proof_hack);

        return secp256k1_dleag_verify(
            m_ctx,
            proof,
            proof_length,
            &secp256k1_generator_const_g,
            &secp256k1_generator_const_h,
            ed25519_gen,
            ed25519_gen2);
    }

    secp256k1_context *m_ctx;
};

#include <emscripten.h>
#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(crypto_lib) {
    class_<CryptoLib>("CryptoLib")
        .constructor<>()
        .function("initialise", &CryptoLib::initialise)
        .function("finalise", &CryptoLib::finalise)
        .function("GetPubKey", &CryptoLib::GetPubKey, allow_raw_pointers())
        .function("ed25519_scm_base", &CryptoLib::ed25519_scm_base, allow_raw_pointers())

        .function("dleag_size", &CryptoLib::dleag_size)
        .function("dleag_prove", &CryptoLib::dleag_prove, allow_raw_pointers())
        .function("dleag_verify", &CryptoLib::dleag_verify, allow_raw_pointers())
        ;
}
