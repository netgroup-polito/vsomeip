// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_AES_CCM_HPP
#define VSOMEIP_AES_CCM_HPP

#include "aead_algorithm_impl.hpp"

namespace vsomeip {

/**
 * \brief Class implementing the AES-CCM AEAD algorithm.
 */
template <aes_key_length AES_KEY_LENGTH>
class aes_ccm : public aead_algorithm_impl {

public:
    const static size_t KEY_LENGTH_BIT = static_cast<size_t>(AES_KEY_LENGTH);
    const static size_t IV_LENGTH_BIT = 96;
    const static size_t TAG_LENGTH_BIT = 128;
    const static size_t KEY_LENGTH = KEY_LENGTH_BIT / 8;
    const static size_t IV_LENGTH = IV_LENGTH_BIT / 8;
    const static size_t TAG_LENGTH = TAG_LENGTH_BIT / 8;

public:
    aes_ccm(secure_vector<byte_t> _key, crypto_instance_t _instance_id);

    aes_ccm(const aes_ccm &) = delete;

    aes_ccm &operator=(const aes_ccm &) = delete;

    ~aes_ccm() override = default;

    bool encipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                  std::vector<byte_t> &_output) override;

    bool decipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                  std::vector<byte_t> &_output) override;
};

} // namespace vsomeip

#endif //VSOMEIP_AES_CCM_HPP
