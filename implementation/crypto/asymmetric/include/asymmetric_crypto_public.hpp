// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ASYMMETRIC_CRYPTO__PUBLIC_HPP
#define VSOMEIP_ASYMMETRIC_CRYPTO__PUBLIC_HPP

#include <vector>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip {

/**
 * \brief Interface representing an Asymmetric Cryptography Public Key.
 *
 * This class provides an abstraction of the operations that can be executed
 * by using the public key of an asymmetric cryptography algorithm. It is
 * exploited to allow an easy replacement of one implementation with another,
 * granting the final users the capability to choose the most suitable algorithm
 * through configurations. The actual implementations of this interface are
 * required to be thread-safe, so that the concurrent execution of the different
 * methods is safe.
 */
class asymmetric_crypto_public {

public:
    virtual ~asymmetric_crypto_public() = default;

    /// \brief Returns whether the current instance has been correctly initialized or not.
    virtual bool is_valid() = 0;

    /**
     * \brief Verifies a digital signature computed across the input data.
     *
     * @param _data the pointer to the beginning of the data to be verified.
     * @param _size the size in bytes of the data to be verified.
     * @param _signature the pointer to the beginning of the signature.
     * @param _signature_size the size in bytes of the signature.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool verify(const byte_t *_data, size_t _size, const byte_t *_signature, size_t _signature_size) = 0;

    /**
     * \brief Enciphers the data provided in input with the public key.
     *
     * @param _data the pointer to the beginning of the data to be enciphered.
     * @param _size the size in bytes of the data to be deciphered.
     * @param _output the reference to the array where the enciphered data is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool encipher(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) = 0;
};

} // namespace vsomeip


#endif //VSOMEIP_ASYMMETRIC_CRYPTO__PUBLIC_HPP
