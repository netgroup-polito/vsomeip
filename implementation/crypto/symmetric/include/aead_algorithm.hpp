// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_AEAD_ALGORITHM_HPP
#define VSOMEIP_AEAD_ALGORITHM_HPP

#include <vector>

#include <vsomeip/primitive_types.hpp>
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Interface representing an Authenticated Encryption with Associated Data algorithm.
 *
 * This class provides an abstraction of an AEAD algorithm, by defining the different
 * functions that need to be provided to protect confidentiality-level services.
 * It is exploited to allow an easy replacement of one implementation with another,
 * granting the final users the capability to choose the most suitable algorithm
 * through configurations. The actual implementation of this interface is *not*
 * required *neither* guaranteed to be thread-safe: external synchronization is
 * necessary if the same object is used to perform parallel encipherments and
 * decipherments.
 */
class aead_algorithm {
public:
    virtual ~aead_algorithm() = default;

    /**
     * \brief Enciphers the data provided in input and computes the associated MAC.
     *
     * This functions applies the AEAD algorithm to the data provided in input,
     * enciphering the bytes from position _associated_data_length up to _size
     * and computing the MAC across the whole array. This distinction allows to
     * have an initial part of the message which is only authenticated (the header),
     * while the actual payload is both authenticated and enciphered.
     *
     * @param _data the pointer to the beginning of the data to be *signed* and partially *enciphered*.
     * @param _associated_data_length the size in bytes of the data to be only *signed*.
     * @param _size the size in bytes of the data to be processed.
     * @param _output the output vector where the result (input -- partially enciphered +
     * support data + MAC) is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool encipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                          std::vector<byte_t> &_output) = 0;

    /**
    * \brief Deciphers the data provided in input and verifies the associated MAC.
    *
    * This functions applies the AEAD algorithm to the data provided in input,
    * deciphering the bytes from position _associated_data_length up to _size
    * and verifying the MAC across the whole array. This distinction allows to
    * have an initial part of the message which is only authenticated (the header),
    * while the actual payload is both authenticated and enciphered.
    *
    * @param _data the pointer to the beginning of the data to be *verified* and
    * partially *deciphered* (input -- partially enciphered + support data + MAC).
    * @param _associated_data_length the size in bytes of the data to be only *verified*.
    * @param _size the size in bytes of the data to be processed.
    * @param _output the output vector where the authenticated and deciphered data is stored.
    * @return a value indicating whether the operation succeeded or not.
    */
    virtual bool decipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                          std::vector<byte_t> &_output) = 0;

    /**
     * \brief Computes the length of the data after having appended the information
     * used for *signature* verification and payload decryption.
     *
     * This function assumes the actual implementation to exploit cryptographic algorithms
     * operating in stream mode, thus not requiring an additional padding in case of
     * data whose length is not a multiple of the basic block.
     *
     * @param _input_length the length of the data in input.
     * @return the computed value.
     */
    virtual size_t get_enciphered_output_length(size_t _input_length) const = 0;

    /**
     * \brief Computes the length of the data after having removed the
     * information used for *signature* verification.
     *
     * This function assumes the actual implementation to exploit cryptographic algorithms
     * operating in stream mode, thus not requiring an additional padding in case of
     * data whose length is not a multiple of the basic block.
     *
     * @param _input_length the length of the data in input.
     * @return the computed value.
     */
    virtual size_t get_deciphered_output_length(size_t _input_length) const = 0;

    /**
     * \brief Stores a new allowed communication peer.
     *
     * This function adds the specified instance ID to the set of the allowed peers
     * for the current communication, which is checked for replay protection.
     *
     * @param _instance_id the ID to be added.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool add_allowed_peer(crypto_instance_t _instance_id) = 0;
};

} // namespace vsomeip

#endif //VSOMEIP_AEAD_ALGORITHM_HPP
