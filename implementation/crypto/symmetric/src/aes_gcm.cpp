// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/aes_gcm.hpp"

#include <openssl/evp.h>

namespace vsomeip {

/* Explicit template instantiation */
template class aes_gcm<aes_key_length::AES_128>;
template class aes_gcm<aes_key_length::AES_256>;

const EVP_CIPHER *get_cipher_gcm(const aes_key_length _key_length) {
    return aes_key_length::AES_128 == _key_length
           ? EVP_aes_128_gcm()
           : EVP_aes_256_gcm();
}

template<aes_key_length AES_KEY_LENGTH>
aes_gcm<AES_KEY_LENGTH>::aes_gcm(secure_vector<byte_t> _key, crypto_instance_t _instance_id)
        : aead_algorithm_impl(get_cipher_gcm(AES_KEY_LENGTH), std::move(_key), TAG_LENGTH, _instance_id) {
}

} // namespace vsomeip
