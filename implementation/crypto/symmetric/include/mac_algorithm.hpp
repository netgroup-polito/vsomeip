// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MAC_ALGORITHM_HPP
#define VSOMEIP_MAC_ALGORITHM_HPP

#include <vector>

#include <vsomeip/primitive_types.hpp>
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Interface representing a Message Authentication Code algorithm.
 *
 * This class provides an abstraction of a MAC algorithm, by defining the different
 * functions that need to be provided to protect authentication-level services.
 * It is exploited to allow an easy replacement of one implementation with another,
 * granting the final users the capability to choose the most suitable algorithm
 * through configurations. The actual implementation of this interface is *not*
 * required *neither* guaranteed to be thread-safe: external synchronization is
 * necessary if the same object is used to perform parallel signatures and
 * verifications.
 */
class mac_algorithm {
public:
    virtual ~mac_algorithm() = default;

    /**
     * \brief Computes and affixes the MAC, together with any necessary information,
     * at the end of the data provided in input.
     *
     * @param _data the pointer to the beginning of the data to be *signed*.
     * @param _size the size in bytes of the data to be *signed*.
     * @param _output the output vector where the result (input + support data + MAC) is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) = 0;

    /**
     * \brief Verifies the MAC code associated to the data provided in input and, in case of
     * match, extracts and returns the authenticated information.
     *
     * @param _data the pointer to the beginning of the data to be *verified* (input + support data + MAC).
     * @param _size the size in bytes of the data to be *verified*.
     * @param _output the output vector where the authenticated data is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool verify(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) = 0;

    /**
     * \brief Computes the length of the data after having appended the
     * information used for *signature* verification.
     *
     * @param _input_length the length of the data in input.
     * @return the computed value.
     */
    virtual size_t get_signed_output_length(size_t _input_length) const = 0;

    /**
     * \brief Computes the length of the data after having removed the
     * information used for *signature* verification.
     *
     * @param _input_length the length of the data in input.
     * @return the computed value.
     */
    virtual size_t get_verified_output_length(size_t _input_length) const = 0;

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

#endif //VSOMEIP_MAC_ALGORITHM_HPP
