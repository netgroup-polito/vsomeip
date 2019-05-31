// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_RSA_PUBLIC_HPP
#define VSOMEIP_RSA_PUBLIC_HPP

#include "asymmetric_crypto_public.hpp"
#include "../../common/include/algorithms.hpp"
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Class implementing the vsomeip::asymmetric_crypto_public
 * interface with the RSA asymmetric algorithm.
 */
class rsa_public : public asymmetric_crypto_public {

public:
    /**
     * \brief Creates a new instance of this class.
     *
     * @param _public_key the OpenSSl object representing the public key.
     * @param _key_length the expected RSA key length (in bits).
     * @param _digest_algorithm the digest algorithm to be used in conjunction with RSA.
     */
    rsa_public(EVP_PKEY_ptr _public_key, rsa_key_length _key_length, digest_algorithm _digest_algorithm);

    rsa_public(const rsa_public &) = delete;

    rsa_public &operator=(const rsa_public &) = delete;

    ~rsa_public() override = default;

    bool is_valid() override;

    bool verify(const byte_t *_data, size_t _size, const byte_t *_signature, size_t _signature_size) override;

    bool encipher(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) override;

private:
    const rsa_key_length key_length_;

    const EVP_PKEY_ptr public_key_;
    const EVP_MD *digest_function_;
};

} // namespace vsomeip

#endif //VSOMEIP_RSA_PUBLIC_HPP
