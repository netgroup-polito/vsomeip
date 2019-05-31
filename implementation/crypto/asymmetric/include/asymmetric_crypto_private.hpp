// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ASYMMETRIC_CRYPTO__PRIVATE_HPP
#define VSOMEIP_ASYMMETRIC_CRYPTO__PRIVATE_HPP

#include <vector>
#include <vsomeip/primitive_types.hpp>
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Interface representing an Asymmetric Cryptography Private Key.
 *
 * This class provides an abstraction of the operations that can be executed
 * by using the private key of an asymmetric cryptography algorithm. It is
 * exploited to allow an easy replacement of one implementation with another,
 * granting the final users the capability to choose the most suitable algorithm
 * through configurations. The actual implementations of this interface is
 * required to be thread-safe, so that the concurrent execution of the different
 * methods is safe.
 */
class asymmetric_crypto_private {

public:
    virtual ~asymmetric_crypto_private() = default;

    /// \brief Returns whether the current instance has been correctly initialized or not.
    virtual bool is_valid() = 0;

    /**
     * \brief Computes a digital signature across the input data.
     *
     * @param _data the pointer to the beginning of the data to be signed.
     * @param _size the size in bytes of the data to be signed.
     * @param _signature the reference to the array where the signature is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_signature) = 0;

    /**
     * \brief Returns the size in bytes of a digital signature.
     *
     * @param _data_length the amount of data to be signed (in bytes).
     * @return the computed digital signature size.
     */
    virtual size_t get_signature_length(size_t _data_length) = 0;

    /**
     * \brief Deciphers the data encrypted with the corresponding public key.
     *
     * @param _data the pointer to the beginning of the data to be deciphered.
     * @param _size the size in bytes of the data to be deciphered.
     * @param _output the reference to the array where the deciphered data is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool decipher(const byte_t *_data, size_t _size, secure_vector<byte_t> &_output) = 0;

    /**
     * \brief Deciphers the data encrypted with the corresponding public key.
     *
     * @param _data the pointer to the beginning of the data to be deciphered.
     * @param _size the size in bytes of the data to be deciphered.
     * @return an array containing the deciphered data (empty in case of error).
     */
    virtual secure_vector<byte_t> decipher(const byte_t *_data, size_t _size) = 0;
};

} // namespace vsomeip


#endif //VSOMEIP_ASYMMETRIC_CRYPTO__PRIVATE_HPP
