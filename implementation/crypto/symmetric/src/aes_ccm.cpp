// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/aes_ccm.hpp"

#include <openssl/evp.h>

#include "../../../logging/include/logger.hpp"

namespace vsomeip {

/* Explicit template instantiation */
template class aes_ccm<aes_key_length::AES_128>;
template class aes_ccm<aes_key_length::AES_256>;

const EVP_CIPHER *get_cipher_ccm(const aes_key_length _key_length) {
    return aes_key_length::AES_128 == _key_length
           ? EVP_aes_128_ccm()
           : EVP_aes_256_ccm();
}

template<aes_key_length AES_KEY_LENGTH>
aes_ccm<AES_KEY_LENGTH>::aes_ccm(secure_vector<byte_t> _key, crypto_instance_t _instance_id)
        : aead_algorithm_impl(get_cipher_ccm(AES_KEY_LENGTH), std::move(_key), TAG_LENGTH, _instance_id) {
}

template<aes_key_length AES_KEY_LENGTH>
bool aes_ccm<AES_KEY_LENGTH>::encipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                                       std::vector<byte_t> &_output) {

    const size_t confidential_data_length = _size - _associated_data_length;
    if (_associated_data_length > _size || confidential_data_length > _size ||
        _size > std::numeric_limits<int>::max()) {
        return false;
    }

    if (!increment_encipher_iv()) {
        return false;
    }

    try {
        _output.resize(get_enciphered_output_length(_size));
    } catch (std::bad_alloc &) {
        return false;
    }

    auto associated_data_ptr = _data;
    auto confidential_input_ptr = _data + _associated_data_length;
    auto confidential_output_ptr = std::copy(_data, confidential_input_ptr, _output.begin());
    const auto iv_ptr = confidential_output_ptr + confidential_data_length;
    const auto tag_ptr = std::copy(encipher_iv_.begin(), encipher_iv_.end(), iv_ptr);

    int out_length;
    bool success =
            /* Initialize the context */
            1 == EVP_EncryptInit_ex(context_.get(), cipher_, nullptr, nullptr, nullptr) &&
            /* Configure IV length */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_CCM_SET_IVLEN, IV_LENGTH, nullptr) &&
            /* Configure tag length */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_CCM_SET_TAG, static_cast<int>(tag_length_), nullptr) &&
            /* Initialize key and IV */
            1 == EVP_EncryptInit_ex(context_.get(), nullptr, nullptr, key_.data(), encipher_iv_.begin()) &&
            /* Specify the total plaintext length */
            1 == EVP_EncryptUpdate(context_.get(), nullptr, &out_length, nullptr,
                                   static_cast<int>(confidential_data_length)) &&
            /* Associated data */
            1 == EVP_EncryptUpdate(context_.get(), nullptr, &out_length, associated_data_ptr,
                                   static_cast<int>(_associated_data_length)) &&
            out_length == static_cast<int>(_associated_data_length) &&
            /* Confidential data */
            1 == EVP_EncryptUpdate(context_.get(), &(*confidential_output_ptr), &out_length,
                                   confidential_input_ptr, static_cast<int>(confidential_data_length)) &&
            out_length == static_cast<int>(confidential_data_length) &&
            /* Finalization (no data written) */
            1 == EVP_EncryptFinal_ex(context_.get(), &(*confidential_output_ptr), &out_length) &&
            0 == out_length &&
            /* Authentication tag */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_CCM_GET_TAG, static_cast<int>(tag_length_),
                                     static_cast<void *>(&(*tag_ptr)));

    /* Reset the context */
    success = 1 == EVP_CIPHER_CTX_reset(context_.get()) && success;

    if (!success) {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("aead_algorithm_impl::encipher failed");
    }

    return success;
}

template<aes_key_length AES_KEY_LENGTH>
bool aes_ccm<AES_KEY_LENGTH>::decipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                                   std::vector<byte_t> &_output) {

    const auto output_size = get_deciphered_output_length(_size);
    const auto confidential_data_length = output_size - _associated_data_length;
    if (_associated_data_length > _size || confidential_data_length > _size ||
        _size > std::numeric_limits<int>::max()) {
        return false;
    }

    try {
        _output.resize(output_size);
    } catch (std::bad_alloc &) {
        return false;
    }

    auto associated_data_ptr = _data;
    auto confidential_input_ptr = _data + _associated_data_length;
    auto confidential_output_ptr = std::copy(_data, confidential_input_ptr, _output.begin());
    const auto iv_ptr = confidential_input_ptr + confidential_data_length;
    const auto tag_ptr = iv_ptr + IV_LENGTH;

    crypto_instance_t instance_id;
    counter_t counter;
    if (!validate_decipher_iv(iv_ptr, instance_id, counter)) {
        return false;
    }

    int out_length;
    bool success =
            /* Initialize the context */
            1 == EVP_DecryptInit_ex(context_.get(), cipher_, nullptr, nullptr, nullptr) &&
            /* Configure IV length */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_CCM_SET_IVLEN, IV_LENGTH, nullptr) &&
            /* Set the expected tag value */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_CCM_SET_TAG, static_cast<int>(tag_length_),
                                     const_cast<void *>(static_cast<const void *>(tag_ptr))) &&
            /* Initialize key and IV */
            1 == EVP_DecryptInit_ex(context_.get(), nullptr, nullptr, key_.data(), iv_ptr) &&
            /* Specify the total ciphertext length */
            1 == EVP_DecryptUpdate(context_.get(), nullptr, &out_length, nullptr,
                                   static_cast<int>(confidential_data_length)) &&
            /* Associated data */
            1 == EVP_DecryptUpdate(context_.get(), nullptr, &out_length, associated_data_ptr,
                                   static_cast<int>(_associated_data_length)) &&
            out_length == static_cast<int>(_associated_data_length) &&
            /* Confidential data */
            1 == EVP_DecryptUpdate(context_.get(), &(*confidential_output_ptr), &out_length,
                                   confidential_input_ptr, static_cast<int>(confidential_data_length)) &&
            out_length == static_cast<int>(confidential_data_length);

    /* Reset the context */
    success = 1 == EVP_CIPHER_CTX_reset(context_.get()) && success;

    if (success) {
        update_decipher_counter(instance_id, counter);
    } else {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("aead_algorithm_impl::decipher failed");
    }

    return success;
}

} // namespace vsomeip
