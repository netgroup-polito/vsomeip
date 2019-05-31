// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_RANDOM_HPP
#define VSOMEIP_RANDOM_HPP

#include <vector>

#include <vsomeip/primitive_types.hpp>
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Interface representing a Random generator.
 *
 * This class provides an abstraction of a Random generator, by defining the
 * different functions that are required to be implemented for the specific
 * situation. The actual implementation of this interface is required
 * to be thread-safe, so that concurrent generation of random data is safe.
 */
class random {
public:
    virtual ~random() = default;

    /**
     * \brief Generates a random array of bytes.
     *
     * @param _size the amount in bytes of random data to be generated.
     * @return the generated array of bytes (empty in case of error).
     */
    virtual secure_vector<byte_t> randomize(size_t _size) = 0;

    /**
     * \brief Generates a random array of bytes.
     *
     * @param _buffer the buffer where the generated data is saved
     * (the amount is specified by its size).
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool randomize(std::vector<byte_t> &_buffer) = 0;

    /**
     * \brief Generates a random array of bytes.
     *
     * @param _buffer the buffer where the generated data is saved
     * (the amount is specified by its size).
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool randomize(secure_vector<byte_t> &_buffer) = 0;

    /**
     * \brief Generates a random array of bytes.
     *
     * @param _buffer the buffer where the generated data is saved.
     * @param _size the amount of random data in bytes to be generated.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool randomize(byte_t *_buffer, size_t _size) = 0;
};

} // namespace vsomeip

#endif //VSOMEIP_RANDOM_HPP
