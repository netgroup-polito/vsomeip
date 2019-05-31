// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_RSA_PRIVATE_HPP
#define VSOMEIP_RSA_PRIVATE_HPP

#include "asymmetric_crypto_private.hpp"
#include "../../common/include/algorithms.hpp"
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Class implementing the vsomeip::asymmetric_crypto_private
 * interface with the RSA asymmetric algorithm.
 */
class rsa_private : public asymmetric_crypto_private {

public:
    /**
     * \brief Creates a new instance of this class.
     *
     * @param _private_key_path the path where the private key is stored.
     * @param _key_length the expected RSA key length (in bits).
     * @param _digest_algorithm the digest algorithm to be used in conjunction with RSA.
     */
    rsa_private(const std::string &_private_key_path, rsa_key_length _key_length, digest_algorithm _digest_algorithm);

    rsa_private(const rsa_private &) = delete;

    rsa_private &operator=(const rsa_private &) = delete;

    ~rsa_private() override = default;

    bool is_valid() override;

    bool sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_signature) override;

    size_t get_signature_length(size_t _data_length) override;

    bool decipher(const byte_t *_data, size_t _size, secure_vector<byte_t> &_output) override;

    secure_vector<byte_t> decipher(const byte_t *_data, size_t _size) override;

private:
    const rsa_key_length key_length_;
    const EVP_PKEY_ptr private_key_;
    const EVP_MD *digest_function_;
};

} // namespace vsomeip

#endif //VSOMEIP_RSA_PRIVATE_HPP
