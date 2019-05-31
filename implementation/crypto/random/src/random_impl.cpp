// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/random_impl.hpp"

#include <openssl/rand.h>
#include "../../../logging/include/logger.hpp"

namespace vsomeip {

secure_vector<byte_t> random_impl::randomize(size_t _size) {

    secure_vector<byte_t> buffer(_size);
    if (!randomize(buffer.data(), buffer.size())) {
        buffer.clear();
    }
    return buffer;
}

bool random_impl::randomize(std::vector<byte_t> &_buffer) {
    return randomize(_buffer.data(), _buffer.size());
}

bool random_impl::randomize(secure_vector<byte_t> &_buffer) {
    return randomize(_buffer.data(), _buffer.size());
}

bool random_impl::randomize(byte_t *_buffer, size_t _size) {
    std::lock_guard<std::mutex> lock(random_mutex_);

    while(_size > 0) {
        const auto chunk_size = _size > std::numeric_limits<int>::max()
                                ? std::numeric_limits<int>::max()
                                : static_cast<int>(_size);

        if (1 != RAND_bytes(_buffer, chunk_size)) {
            VSOMEIP_ERROR << get_openssl_errors("random_impl::randomize failed");
            return false;
        };

        _buffer += chunk_size;
        _size -= static_cast<size_t>(chunk_size);
    }
    return true;
}

}
