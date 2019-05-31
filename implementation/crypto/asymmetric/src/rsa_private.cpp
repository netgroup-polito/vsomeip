// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/rsa_private.hpp"

#include <cstdio>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "../../../logging/include/logger.hpp"

namespace vsomeip {

/**
 * \brief Reads and validates a private key from a file and returns the corresponding OpenSSL object.
 *
 * @param _path the path where the private key is stored.
 * @param _key_length the expected key length.
 * @return the obtained OpenSSL object or nullptr in case of error.
 */
static EVP_PKEY_ptr rsa_read_private_key(const std::string &_path, rsa_key_length _key_length) {

    FILE *file;
    if (nullptr == (file = std::fopen(_path.data(), "r"))) {
        VSOMEIP_ERROR << "Failed to open private key file '" << _path << "'";
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    RSA_ptr key(PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr), ::RSA_free);
    std::fclose(file);

    if (!key) {
        VSOMEIP_ERROR << get_openssl_errors("failed to read private key file '" + _path + "'");
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    if (!RSA_check_key(key.get())) {
        VSOMEIP_ERROR << get_openssl_errors("failed to validate private key file '" + _path + "'");
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    auto actual_key_length = static_cast<size_t>(RSA_size(key.get())) * 8;
    if (static_cast<size_t>(_key_length) != actual_key_length) {
        VSOMEIP_ERROR << "Failed to validate private key file '" << _path << "' - expected length "
                      << static_cast<size_t>(_key_length) << " found " << actual_key_length;
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    EVP_PKEY_ptr evp_pkey(::EVP_PKEY_new(), ::EVP_PKEY_free);
    if (evp_pkey) {
        EVP_PKEY_assign_RSA(evp_pkey.get(), key.release());
    }
    return evp_pkey;
}

rsa_private::rsa_private(const std::string &_private_key_path, rsa_key_length _key_length,
                         digest_algorithm _digest_algorithm)
        : key_length_(_key_length), private_key_(rsa_read_private_key(_private_key_path, _key_length)) {

    switch (_digest_algorithm) {
        case digest_algorithm::MD_SHA256:
            digest_function_ = EVP_sha256();
            break;
    }
}

bool rsa_private::is_valid() {
    return static_cast<bool>(private_key_) && nullptr != digest_function_;
}

bool rsa_private::sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_signature) {

    if (!is_valid()) {
        VSOMEIP_ERROR << "Trying to use an invalid instance of rsa_private";
        return false;
    }

    const EVP_MD_CTX_ptr context(::EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    if (!context) {
        VSOMEIP_ERROR << "Failed to create a EVP_MD_CTX object";
        return false;
    }

    size_t signature_length;
    bool success =
            /* Initialization */
            1 == EVP_DigestSignInit(context.get(), nullptr, digest_function_, nullptr, private_key_.get()) &&
            /* Set data */
            1 == EVP_DigestSignUpdate(context.get(), _data, _size) &&
            /* Get signature length */
            1 == EVP_DigestSignFinal(context.get(), nullptr, &signature_length);


    if (success) {
        try {
            _signature.resize(signature_length);
        } catch (std::bad_alloc &) {
            return false;
        }

        /* Finalization */
        success = 1 == EVP_DigestSignFinal(context.get(), _signature.data(), &signature_length);
    }

    if (!success) {
        _signature.clear();
        VSOMEIP_ERROR << get_openssl_errors("rsa_private::sign failed");
    }

    return success;
}

size_t rsa_private::get_signature_length(size_t _data_length) {
    (void) _data_length;
    // Signature length does not depend on the data length
    return (static_cast<size_t>(key_length_) / 8);
}

bool rsa_private::decipher(const byte_t *_data, size_t _size, secure_vector<byte_t> &_output) {

    if (!is_valid()) {
        VSOMEIP_ERROR << "Trying to use an invalid instance of rsa_private";
        return false;
    }

    const EVP_PKEY_CTX_ptr context(::EVP_PKEY_CTX_new(private_key_.get(), nullptr), ::EVP_PKEY_CTX_free);
    if (!context) {
        VSOMEIP_ERROR << "Failed to create a EVP_PKEY_CTX object";
        return false;
    }

    size_t output_length;
    bool success =
            /* Initialization */
            1 == EVP_PKEY_decrypt_init(context.get()) &&
            /* Set padding */
            1 == EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_PADDING) &&
            /* Get output length */
            1 == EVP_PKEY_decrypt(context.get(), nullptr, &output_length, _data, _size);

    if (success) {
        try {
            _output.resize(output_length);
        } catch (std::bad_alloc &) {
            return false;
        }

        /* Decrypt */
        success = 1 == EVP_PKEY_decrypt(context.get(), _output.data(), &output_length, _data, _size);
    }

    if (success) {
        _output.resize(output_length);
    } else {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("rsa_private::decipher failed");
    }

    return success;
}

secure_vector<byte_t> rsa_private::decipher(const byte_t *_data, size_t _size) {
    secure_vector<byte_t> buffer;
    decipher(_data, _size, buffer);
    return buffer;
}

} // namespace vsomeip
