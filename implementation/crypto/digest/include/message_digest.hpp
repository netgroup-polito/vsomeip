// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_DIGEST_HPP
#define VSOMEIP_MESSAGE_DIGEST_HPP

#include <vsomeip/primitive_types.hpp>
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Interface representing a Message Digest algorithm.
 *
 * This class provides an abstraction of a Message Digest algorithm, by defining
 * the different functions that are required to be implemented for the specific
 * situation. The actual implementation of this interface is required to be
 * thread-safe, so that concurrent computations of message digests are safe.
 */
class message_digest {
public:
    virtual ~message_digest() = default;

    /**
     * \brief Returns the length in bytes of computed message digests.
     */
    virtual size_t digest_length() const = 0;

    /**
     * \brief Computes the message digest corresponding to the input data.
     *
     * @param _input the pointer to the beginning of the input data.
     * @param _size the size in bytes of the input data.
     * @param _buffer the pointer to the beginning of the buffer where the result is
     * stored (it is assumed to be able to contain at least digest_length() bytes).
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool compute_digest(const byte_t *_input, size_t _size, byte_t *_buffer) = 0;

    /**
     * \brief Computes the message digest corresponding to the input file.
     *
     * @param _input_file the path to the input file whose message digest is computed.
     * @param _buffer the pointer to the beginning of the buffer where the result is
     * stored (it is assumed to be able to contain at least digest_length() bytes).
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool compute_digest(std::string _input_file, byte_t *_buffer) = 0;
};

} // namespace vsomeip

#endif //VSOMEIP_MESSAGE_DIGEST_HPP
