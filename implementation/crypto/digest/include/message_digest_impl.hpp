// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_DIGEST_IMPL_HPP
#define VSOMEIP_MESSAGE_DIGEST_IMPL_HPP

#include "message_digest.hpp"
#include "../../common/include/algorithms.hpp"
#include "../../common/include/crypto_types.hpp"

#include <openssl/ossl_typ.h>

namespace vsomeip {

/**
 * \brief The actual implementation of the vsomeip::message_digest interface.
 */
class message_digest_impl : public message_digest {
public:
    /**
     * Creates a new instance of this class.
     *
     * @param _digest_algorithm the identifier of the chosen message digest algorithm.
     */
    explicit message_digest_impl(digest_algorithm _digest_algorithm);

    ~message_digest_impl() override = default;

    size_t digest_length() const override;

    bool compute_digest(const byte_t *_input, size_t _size, byte_t *_buffer) override;

    bool compute_digest(std::string _input_file, byte_t *_buffer) override;

private:
    const EVP_MD *digest_algorithm_;
    size_t digest_length_;
};

} // namespace vsomeip

#endif //VSOMEIP_MESSAGE_DIGEST_IMPL_HPP
