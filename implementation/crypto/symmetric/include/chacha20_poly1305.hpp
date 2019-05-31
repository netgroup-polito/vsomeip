// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CHACHA20_POLY1305_HPP
#define VSOMEIP_CHACHA20_POLY1305_HPP

#include "aead_algorithm_impl.hpp"

namespace vsomeip {

/**
 * \brief Class implementing the CHACHA20-POLY1305 AEAD algorithm.
 */
class chacha20_poly1305 : public aead_algorithm_impl {

public:
    const static size_t KEY_LENGTH_BIT = 256;
    const static size_t IV_LENGTH_BIT = 96;
    const static size_t TAG_LENGTH_BIT = 128;
    const static size_t KEY_LENGTH = KEY_LENGTH_BIT / 8;
    const static size_t IV_LENGTH = IV_LENGTH_BIT / 8;
    const static size_t TAG_LENGTH = TAG_LENGTH_BIT / 8;

public:
    chacha20_poly1305(secure_vector<byte_t> _key, crypto_instance_t _instance_id);

    chacha20_poly1305(const chacha20_poly1305 &) = delete;

    chacha20_poly1305 &operator=(const chacha20_poly1305 &) = delete;

    ~chacha20_poly1305() override = default;
};

} // namespace vsomeip

#endif //VSOMEIP_CHACHA20_POLY1305_HPP
