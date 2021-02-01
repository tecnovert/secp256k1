// Copyright (c) 2020-2021 tecnovert
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <secp256k1.h>
#include <secp256k1_ed25519.h>
#include <secp256k1_dleag.h>
#include <secp256k1_ecdsaotves.h>
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

    int GetPubKey(uintptr_t result_hack, const uintptr_t key_hack) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<const unsigned char*>(key_hack);

        secp256k1_pubkey pubkey;
        size_t clen = 33;
        int ret = secp256k1_ec_pubkey_create(m_ctx, &pubkey, key);
        if (ret != 1) {
            return 1;
        }
        secp256k1_ec_pubkey_serialize(m_ctx, result, &clen, &pubkey, SECP256K1_EC_COMPRESSED);
        return 0;
    }

    int ed25519_scm_base(uintptr_t result_hack, const uintptr_t key_hack) const
    {
        return crypto_scalarmult_ed25519_base_noclamp(
            reinterpret_cast<unsigned char*>(result_hack),
            reinterpret_cast<const unsigned char*>(key_hack));
    }

    void ed25519_scadd(uintptr_t z_hack, const uintptr_t x_hack, const uintptr_t y_hack) const
    {
        crypto_core_ed25519_scalar_add(
            reinterpret_cast<unsigned char*>(z_hack),
            reinterpret_cast<const unsigned char*>(x_hack),
            reinterpret_cast<const unsigned char*>(y_hack));
    }

    int ed25519_add(uintptr_t z_hack, const uintptr_t x_hack, const uintptr_t y_hack) const
    {
        return crypto_core_ed25519_add(
            reinterpret_cast<unsigned char*>(z_hack),
            reinterpret_cast<const unsigned char*>(x_hack),
            reinterpret_cast<const unsigned char*>(y_hack));
    }

    int dleag_size(int num_bits)
    {
        return secp256k1_dleag_size(num_bits);
    }

    int dleag_prove(uintptr_t result_hack, const uintptr_t key_hack, const uintptr_t nonce_hack, int num_bits) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<const unsigned char*>(key_hack);
        const unsigned char *nonce = reinterpret_cast<const unsigned char*>(nonce_hack);

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

    int dleag_prove_le(uintptr_t result_hack, const uintptr_t key_hack, const uintptr_t nonce_hack, int num_bits) const
    {
        unsigned char *result = reinterpret_cast<unsigned char*>(result_hack);
        const unsigned char *key = reinterpret_cast<const unsigned char*>(key_hack);
        const unsigned char *nonce = reinterpret_cast<const unsigned char*>(nonce_hack);

        unsigned char key_be[32];
        for (int i = 0; i < 32; ++i) {
            key_be[i] = key[31 - i];
        }

        size_t proof_len = secp256k1_dleag_size(num_bits);
        int rv = secp256k1_dleag_prove(
            m_ctx,
            result,
            &proof_len,
            key_be,
            num_bits,
            nonce,
            &secp256k1_generator_const_g,
            &secp256k1_generator_const_h,
            ed25519_gen,
            ed25519_gen2);
        sodium_memzero(key_be, 32);
        return rv;
    }

    int dleag_verify(const uintptr_t proof_hack, int proof_length) const
    {
        return secp256k1_dleag_verify(
            m_ctx,
            reinterpret_cast<const unsigned char*>(proof_hack),
            proof_length,
            &secp256k1_generator_const_g,
            &secp256k1_generator_const_h,
            ed25519_gen,
            ed25519_gen2);
    }

    int ecdsaotves_enc_sign(uintptr_t ct_out_h, const uintptr_t skS_h, const uintptr_t pkE_h, const uintptr_t msg32_h) const
    {
        return ::ecdsaotves_enc_sign(
            m_ctx,
            reinterpret_cast<unsigned char*>(ct_out_h),
            reinterpret_cast<const unsigned char*>(skS_h),
            reinterpret_cast<const unsigned char*>(pkE_h),
            reinterpret_cast<const unsigned char*>(msg32_h));
    }

    int ecdsaotves_enc_verify(const uintptr_t pkS, const uintptr_t pkE, const uintptr_t msg32, const uintptr_t ct) const
    {
        return ::ecdsaotves_enc_verify(
            m_ctx,
            reinterpret_cast<const unsigned char*>(pkS),
            reinterpret_cast<const unsigned char*>(pkE),
            reinterpret_cast<const unsigned char*>(msg32),
            reinterpret_cast<const unsigned char*>(ct));
    }

    int ecdsaotves_dec_sig(uintptr_t sig_out, uintptr_t sig_length, const uintptr_t skE, const uintptr_t ct) const
    {
        return ::ecdsaotves_dec_sig(
            m_ctx,
            reinterpret_cast<unsigned char*>(sig_out),
            reinterpret_cast<size_t*>(sig_length),
            reinterpret_cast<const unsigned char*>(skE),
            reinterpret_cast<const unsigned char*>(ct));
    }

    int ecdsaotves_rec_enc_key(const uintptr_t key_out, const uintptr_t pkE, const uintptr_t ct, const uintptr_t dersig, int sig_length) const
    {
        return ::ecdsaotves_rec_enc_key(
            m_ctx,
            reinterpret_cast<unsigned char*>(key_out),
            reinterpret_cast<const unsigned char*>(pkE),
            reinterpret_cast<const unsigned char*>(ct),
            reinterpret_cast<const unsigned char*>(dersig),
            sig_length);
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
        .function("ed25519_scadd", &CryptoLib::ed25519_scadd, allow_raw_pointers())
        .function("ed25519_add", &CryptoLib::ed25519_add, allow_raw_pointers())

        .function("dleag_size", &CryptoLib::dleag_size)
        .function("dleag_prove", &CryptoLib::dleag_prove, allow_raw_pointers())
        .function("dleag_prove_le", &CryptoLib::dleag_prove_le, allow_raw_pointers())
        .function("dleag_verify", &CryptoLib::dleag_verify, allow_raw_pointers())
        .function("ecdsaotves_enc_sign", &CryptoLib::ecdsaotves_enc_sign, allow_raw_pointers())
        .function("ecdsaotves_enc_verify", &CryptoLib::ecdsaotves_enc_verify, allow_raw_pointers())
        .function("ecdsaotves_dec_sig", &CryptoLib::ecdsaotves_dec_sig, allow_raw_pointers())
        .function("ecdsaotves_rec_enc_key", &CryptoLib::ecdsaotves_rec_enc_key, allow_raw_pointers())
        ;
}
