// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/chacha20_poly1305.hpp"

#include <openssl/evp.h>

namespace vsomeip {

chacha20_poly1305::chacha20_poly1305(secure_vector<byte_t> _key, crypto_instance_t _instance_id)
        : aead_algorithm_impl(EVP_chacha20_poly1305(), std::move(_key), TAG_LENGTH, _instance_id) {
}

} // namespace vsomeip
