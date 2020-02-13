// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/aead_algorithm_impl.hpp"

#include <openssl/evp.h>

#include "../../../logging/include/logger.hpp"
#include "../../../utility/include/byteorder.hpp"

namespace vsomeip {

aead_algorithm_impl::counter_diff_t operator-(
        aead_algorithm_impl::counter_t _lhs,
        aead_algorithm_impl::counter_t _rhs) {

    bool positive(true);
    if (_rhs > _lhs) {
        _lhs.swap(_rhs);
        positive = false;
    }

    aead_algorithm_impl::counter_t difference = {
            _lhs.first - _rhs.first,
            _lhs.second - _rhs.second
    };

    if (difference.second > _lhs.second) {
        difference.first -= 1;
    }

    using counter_diff_t = aead_algorithm_impl::counter_diff_t;
    auto counter_diff = (difference.first == 0 && difference.second < std::numeric_limits<counter_diff_t>::max())
                        ? static_cast<counter_diff_t>(difference.second)
                        : std::numeric_limits<counter_diff_t>::max();
    return counter_diff * (positive ? 1 : -1);
}

aead_algorithm_impl::aead_algorithm_impl(const EVP_CIPHER *_cipher, secure_vector<byte_t> _key,
                                         size_t _tag_length,  crypto_instance_t _instance_id)
        : context_(::EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free),
          cipher_(_cipher), key_(std::move(_key)), tag_length_(_tag_length),
          encipher_iv_{0}, encipher_counter_{0, 0} {

    encipher_iv_[2] = VSOMEIP_WORD_BYTE1(_instance_id);
    encipher_iv_[3] = VSOMEIP_WORD_BYTE0(_instance_id);
}

aead_algorithm_impl::~aead_algorithm_impl() = default;

bool aead_algorithm_impl::sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) {
    return encipher(_data, _size, _size, _output);
}

bool aead_algorithm_impl::verify(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) {
    return decipher(_data, _size, get_verified_output_length(_size), _output);
}

bool aead_algorithm_impl::encipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                                   std::vector<byte_t> &_output) {

    const size_t confidential_data_length = _size - _associated_data_length;
    if (_associated_data_length > _size || confidential_data_length > _size) {
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
    bool success = /* Initialization */
            1 == EVP_EncryptInit_ex(context_.get(), cipher_, nullptr, key_.data(), encipher_iv_.begin());

    /* Associated data */
    auto remaining_associated_data_length = _associated_data_length;
    while (success && remaining_associated_data_length > 0) {
        const auto chunk_length = remaining_associated_data_length > std::numeric_limits<int>::max()
                                  ? std::numeric_limits<int>::max()
                                  : static_cast<int>(remaining_associated_data_length);

        success = 1 == EVP_EncryptUpdate(context_.get(), nullptr, &out_length, associated_data_ptr, chunk_length) &&
                  out_length == chunk_length;

        remaining_associated_data_length -= static_cast<size_t>(chunk_length);
        associated_data_ptr += chunk_length;
    }

    /* Confidential data */
    auto remaining_confidential_data_length = confidential_data_length;
    while (success && remaining_confidential_data_length > 0) {
        const auto chunk_length = remaining_confidential_data_length > std::numeric_limits<int>::max()
                                  ? std::numeric_limits<int>::max()
                                  : static_cast<int>(remaining_confidential_data_length);

        success = 1 == EVP_EncryptUpdate(context_.get(), &(*confidential_output_ptr), &out_length,
                                         confidential_input_ptr, chunk_length) &&
                  out_length == chunk_length;

        remaining_confidential_data_length -= static_cast<size_t>(chunk_length);
        confidential_input_ptr += chunk_length;
        confidential_output_ptr += chunk_length;
    }

    success &=
            /* Finalization (no data written) */
            1 == EVP_EncryptFinal_ex(context_.get(), &(*confidential_output_ptr), &out_length) && 0 == out_length &&
            /* Authentication tag */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag_length_),
                                     static_cast<void *>(&(*tag_ptr)));

    success = 1 == EVP_CIPHER_CTX_reset(context_.get()) && success;

    if (!success) {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("aead_algorithm_impl::encipher failed");
    }

    return success;
}

bool aead_algorithm_impl::decipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                                   std::vector<byte_t> &_output) {

    const auto output_size = get_deciphered_output_length(_size);
    const auto confidential_data_length = output_size - _associated_data_length;
    if (_associated_data_length > _size || confidential_data_length > _size) {
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
    bool success = /* Initialization */
            1 == EVP_DecryptInit_ex(context_.get(), cipher_, nullptr, key_.data(), iv_ptr);

    /* Associated data */
    auto remaining_associated_data_length = _associated_data_length;
    while (success && remaining_associated_data_length > 0) {
        const auto chunk_length = remaining_associated_data_length > std::numeric_limits<int>::max()
                                  ? std::numeric_limits<int>::max()
                                  : static_cast<int>(remaining_associated_data_length);

        success = 1 == EVP_DecryptUpdate(context_.get(), nullptr, &out_length, associated_data_ptr, chunk_length) &&
                  out_length == chunk_length;

        remaining_associated_data_length -= static_cast<size_t>(chunk_length);
        associated_data_ptr += chunk_length;
    }

    /* Confidential data */
    auto remaining_confidential_data_length = confidential_data_length;
    while (success && remaining_confidential_data_length > 0) {
        const auto chunk_length = remaining_confidential_data_length > std::numeric_limits<int>::max()
                                  ? std::numeric_limits<int>::max()
                                  : static_cast<int>(remaining_confidential_data_length);

        success = 1 == EVP_DecryptUpdate(context_.get(), &(*confidential_output_ptr), &out_length,
                                         confidential_input_ptr, chunk_length) &&
                  out_length == chunk_length;

        remaining_confidential_data_length -= static_cast<size_t>(chunk_length);
        confidential_input_ptr += chunk_length;
        confidential_output_ptr += chunk_length;
    }

    success &=
            /* Authentication tag (in case of verification/decryption) */
            1 == EVP_CIPHER_CTX_ctrl(context_.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag_length_),
                                     const_cast<void *>(static_cast<const void *>(tag_ptr))) &&
            /* Finalization (no data written) */
            1 == EVP_DecryptFinal_ex(context_.get(), &(*confidential_output_ptr), &out_length) && 0 == out_length;

    success = 1 == EVP_CIPHER_CTX_reset(context_.get()) && success;

    if (success) {
        update_decipher_counter(instance_id, counter);
    } else {
        _output.clear();
        VSOMEIP_ERROR << get_openssl_errors("aead_algorithm_impl::decipher failed");
    }

    return success;
}

size_t aead_algorithm_impl::get_signed_output_length(size_t _input_length) const {
    return get_enciphered_output_length(_input_length);
}

size_t aead_algorithm_impl::get_verified_output_length(size_t _input_length) const {
    return get_deciphered_output_length(_input_length);
}

size_t aead_algorithm_impl::get_enciphered_output_length(size_t _input_length) const {
    return _input_length + IV_LENGTH + tag_length_;
}

size_t aead_algorithm_impl::get_deciphered_output_length(size_t _input_length) const {
    return _input_length < (IV_LENGTH + tag_length_) ? 0 : _input_length - IV_LENGTH - tag_length_;
}

bool aead_algorithm_impl::add_allowed_peer(crypto_instance_t _instance_id) {
    auto inserted = decipher_counters.insert({_instance_id, {{0, 0}, 0}});
    return inserted.second;
}

bool aead_algorithm_impl::increment_encipher_iv() {
    if (std::numeric_limits<counter_element_t>::max() == encipher_counter_.second) {
        if (std::numeric_limits<counter_element_t>::max() == encipher_counter_.first) {
            return false;
        }

        encipher_counter_.first++;
        encipher_iv_[4] = VSOMEIP_LONG_BYTE3(encipher_counter_.first);
        encipher_iv_[5] = VSOMEIP_LONG_BYTE2(encipher_counter_.first);
        encipher_iv_[6] = VSOMEIP_LONG_BYTE1(encipher_counter_.first);
        encipher_iv_[7] = VSOMEIP_LONG_BYTE0(encipher_counter_.first);
    }

    encipher_counter_.second++;
    encipher_iv_[8] = VSOMEIP_LONG_BYTE3(encipher_counter_.second);
    encipher_iv_[9] = VSOMEIP_LONG_BYTE2(encipher_counter_.second);
    encipher_iv_[10] = VSOMEIP_LONG_BYTE1(encipher_counter_.second);
    encipher_iv_[11] = VSOMEIP_LONG_BYTE0(encipher_counter_.second);
    return true;
}

bool aead_algorithm_impl::validate_decipher_iv(const byte_t *_iv_data, crypto_instance_t &_instance_id,
                                               counter_t &_counter) const {

    uint16_t zero = VSOMEIP_BYTES_TO_WORD(_iv_data[0], _iv_data[1]);
    _instance_id = VSOMEIP_BYTES_TO_WORD(_iv_data[2], _iv_data[3]);
    _counter.first = VSOMEIP_BYTES_TO_LONG(_iv_data[4], _iv_data[5], _iv_data[6], _iv_data[7]);
    _counter.second = VSOMEIP_BYTES_TO_LONG(_iv_data[8], _iv_data[9], _iv_data[10], _iv_data[11]);

    auto found = decipher_counters.find(_instance_id);
    if (0 != zero || found == decipher_counters.end()) {
        VSOMEIP_WARNING << "authenticated_encryption_base::decipher - received a message from an unknown client";
        return false;
    }

    const auto &found_counter = found->second.first;
    auto counter_diff = found_counter - _counter;
    if (counter_diff < 0 /* current newer than first in history */) {
        return true;
    }

    auto found_history = found->second.second;
    bool valid = counter_diff < MAX_HISTORY_LENGTH && /* current not older than last in history */
                 !(static_cast<bool>(found_history & (1u << static_cast<counter_history_idx_t>(counter_diff))));

    if (!valid) {
        VSOMEIP_WARNING << "authenticated_encryption_base::decipher - detected a possibly replayed message";
    }
    return valid;
}

void aead_algorithm_impl::update_decipher_counter(crypto_instance_t _instance_id, counter_t _counter) {

    auto found = decipher_counters.find(_instance_id);
    if (found == decipher_counters.end()) {
        return;
    }

    auto &found_counter = found->second.first;
    auto &found_history = found->second.second;
    auto counter_diff = found_counter - _counter;

    if (counter_diff < 0 /* current newer than first in history */) {
        found_counter.swap(_counter);

        counter_diff = -counter_diff;
        found_history = counter_diff < MAX_HISTORY_LENGTH
                        ? (found_history << static_cast<counter_history_idx_t>(counter_diff)) | 1u
                        : 1u;
    } else if (counter_diff < MAX_HISTORY_LENGTH /* current belongs to history */) {
        found_history |= (1u << static_cast<counter_history_idx_t>(counter_diff));
    }
}

} // namespace vsomeip
