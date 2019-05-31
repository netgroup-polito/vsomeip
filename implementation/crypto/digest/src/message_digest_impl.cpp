// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_digest_impl.hpp"

#include <openssl/evp.h>
#include <fstream>

#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

message_digest_impl::message_digest_impl(digest_algorithm _digest_algorithm) {
    switch (_digest_algorithm) {
        case digest_algorithm::MD_SHA256:
            digest_algorithm_ = EVP_sha256();
            break;
    }
    digest_length_ = digest_algorithm_ ? static_cast<size_t>(EVP_MD_size(digest_algorithm_)) : 0;
}

size_t message_digest_impl::digest_length() const {
    return digest_length_;
}

bool message_digest_impl::compute_digest(const byte_t *_input, size_t _size, byte_t *_buffer) {

    const EVP_MD_CTX_ptr context(::EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    return context &&
           1 == EVP_DigestInit_ex(context.get(), digest_algorithm_, nullptr) &&
           1 == EVP_DigestUpdate(context.get(), _input, _size) &&
           1 == EVP_DigestFinal_ex(context.get(), _buffer, nullptr);
}

bool message_digest_impl::compute_digest(std::string _input_file, byte_t *_buffer) {

    const EVP_MD_CTX_ptr context(::EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
    if (!context || 1 != EVP_DigestInit_ex(context.get(), digest_algorithm_, nullptr)) {
        return false;
    }

    const auto buffer_size = 4096;
    std::vector<char> its_buffer(buffer_size);
    std::ifstream its_file(_input_file);
    if (!its_file.is_open()) {
        return false;
    }

    while (its_file) {
        its_file.read(its_buffer.data(), static_cast<std::streamsize>(its_buffer.size()));
        if (1 != EVP_DigestUpdate(context.get(), its_buffer.data(), static_cast<size_t>(its_file.gcount()))) {
            return false;
        }
    }

    return 1 == EVP_DigestFinal_ex(context.get(), _buffer, nullptr);
}

} // namespace vsomeip