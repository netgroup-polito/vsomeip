// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/rsa_public.hpp"

#include <cstdio>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "../../common/include/crypto_types.hpp"
#include "../../../logging/include/logger.hpp"

namespace vsomeip {

rsa_public::rsa_public(EVP_PKEY_ptr _public_key, rsa_key_length _key_length, digest_algorithm _digest_algorithm)
        : key_length_(_key_length), public_key_(std::move(_public_key)) {

    switch (_digest_algorithm) {
        case digest_algorithm::MD_SHA256:
            digest_function_ = EVP_sha256();
    }
}

bool rsa_public::is_valid() {
    return static_cast<bool>(public_key_) && nullptr != digest_function_;
}

bool rsa_public::verify(const byte_t *_data, size_t _size, const byte_t *_signature, size_t _signature_size) {

    if (!is_valid()) {
        VSOMEIP_ERROR << "Trying to use an invalid instance of rsa_public";
        return false;
    }

    const EVP_MD_CTX_ptr context(::EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    if (!context) {
        return false;
    }

    bool success =
            /* Initialization */
            1 == EVP_DigestVerifyInit(context.get(), nullptr, digest_function_, nullptr, public_key_.get()) &&
            /* Set data */
            1 == EVP_DigestVerifyUpdate(context.get(), _data, _size) &&
            /* Verify signature */
            1 == EVP_DigestVerifyFinal(context.get(), _signature, _signature_size);

    if (!success) {
        VSOMEIP_ERROR << get_openssl_errors("rsa_public::verify failed");
    }

    return success;
}

bool rsa_public::encipher(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) {
    if (!is_valid()) {
        VSOMEIP_ERROR << "Trying to use an invalid instance of rsa_public";
        return false;
    }

    const EVP_PKEY_CTX_ptr context(::EVP_PKEY_CTX_new(public_key_.get(), nullptr), ::EVP_PKEY_CTX_free);
    if (!context) {
        VSOMEIP_ERROR << "Failed to create a EVP_PKEY_CTX_ptr context";
        return false;
    }

    size_t output_length;
    bool success =
            /* Initialization */
            1 == EVP_PKEY_encrypt_init(context.get()) &&
            /* Set padding */
            1 == EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_PADDING) &&
            /* Get output length */
            1 == EVP_PKEY_encrypt(context.get(), nullptr, &output_length, _data, _size);

    if (success) {
        try {
            _output.resize(output_length);
        } catch (std::bad_alloc &) {
            return false;
        }

        /* Encrypt */
        success = 1 == EVP_PKEY_encrypt(context.get(), _output.data(), &output_length, _data, _size);
    }

    if (!success) {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("rsa_public::encipher failed");
    }

    return success;
}

} // namespace vsomeip
