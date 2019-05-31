// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_deserializer.hpp"

#include <vsomeip/defines.hpp>
#include <vsomeip/message.hpp>
#include "../../crypto/symmetric/include/mac_algorithm.hpp"
#include "../../crypto/symmetric/include/aead_algorithm.hpp"
#include "../../logging/include/logger.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../utility/include/byteorder.hpp"
#include "../../utility/include/utility.hpp"

namespace vsomeip {

/**
 * A vsomeip::deserializer wrapper that provides a convenient RAII-style mechanism
 * for resetting the deserializer when the scoped block ends.
 */
class deserializer_handler {
public:
    explicit deserializer_handler(const std::unique_ptr<deserializer> &_handle) : handle_(_handle) {}

    ~deserializer_handler() { handle_->reset(); }

private:
    const std::unique_ptr<deserializer> &handle_;
};

/**
 * Utility function that converts the _message_length value into on-wire format and
 * stores it into the byte array pointed by _data.
 */
static inline void update_message_length(length_t _message_length, byte_t *_data) {
    _data[0] = VSOMEIP_LONG_BYTE3(_message_length);
    _data[1] = VSOMEIP_LONG_BYTE2(_message_length);
    _data[2] = VSOMEIP_LONG_BYTE1(_message_length);
    _data[3] = VSOMEIP_LONG_BYTE0(_message_length);
}

/**
 * Modifies the value pointed by the parameter, by clearing the security flags.
 */
static inline void update_message_type_clear(byte_t *_data) {
    *_data = utility::clear_security_flags(*_data);
}

/* ** MESSAGE DESERIALIZER ** */

message_deserializer::message_deserializer(std::uint32_t _buffer_shrink_threshold)
        : deserializer_(std::unique_ptr<deserializer>(new deserializer(_buffer_shrink_threshold))) {}

message_deserializer::~message_deserializer() = default;

/* ** MESSAGE DESERIALIZER NOSEC ** */

message_deserializer_nosec::message_deserializer_nosec(std::uint32_t _buffer_shrink_threshold)
        : message_deserializer(_buffer_shrink_threshold) {}

message_deserializer_nosec::~message_deserializer_nosec() = default;

message *message_deserializer_nosec::deserialize_message(const byte_t *_data, size_t _size) {

    if (VSOMEIP_PAYLOAD_POS > _size || !utility::is_nosec_level(*(_data + VSOMEIP_MESSAGE_TYPE_POS))) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(deserializer_mutex_);
    deserializer_handler handler(deserializer_);

    deserializer_->set_data(_data, _size);
    return deserializer_->deserialize_message();
}

bool message_deserializer_nosec::add_allowed_peer(crypto_instance_t _instance_id) {
    (void) _instance_id;
    return true;
}

/* ** MESSAGE DESERIALIZER AUTHENTICATION ** */

message_deserializer_authentication::message_deserializer_authentication(std::uint32_t _buffer_shrink_threshold,
                                                                         std::unique_ptr<mac_algorithm> _mac_algorithm)
        : message_deserializer(_buffer_shrink_threshold),
          mac_algorithm_(std::move(_mac_algorithm)) {}

message_deserializer_authentication::~message_deserializer_authentication() = default;

message *message_deserializer_authentication::deserialize_message(const byte_t *_data, size_t _size) {

    if (VSOMEIP_PAYLOAD_POS > _size || !utility::is_authentication_level(*(_data + VSOMEIP_MESSAGE_TYPE_POS))) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(deserializer_mutex_);
    std::vector<byte_t> output;
    if (!mac_algorithm_->verify(_data, _size, output)) {
        return nullptr;
    }

    deserializer_handler handler(deserializer_);
    deserializer_->set_data(output.data(), output.size());

    length_t message_length;
    if (!deserializer_->look_ahead(VSOMEIP_LENGTH_POS_MIN, message_length)) {
        return nullptr;
    }

    update_message_type_clear(deserializer_->get_data() + VSOMEIP_MESSAGE_TYPE_POS);
    update_message_length(static_cast<length_t>(mac_algorithm_->get_verified_output_length(message_length)),
                          deserializer_->get_data() + VSOMEIP_LENGTH_POS_MIN);

    return deserializer_->deserialize_message();
}

bool message_deserializer_authentication::add_allowed_peer(crypto_instance_t _instance_id) {
    std::lock_guard<std::mutex> lock(deserializer_mutex_);
    return mac_algorithm_->add_allowed_peer(_instance_id);
}

/* ** MESSAGE DESERIALIZER CONFIDENTIALITY ** */

message_deserializer_confidentiality::message_deserializer_confidentiality(
        std::uint32_t _buffer_shrink_threshold, std::unique_ptr<aead_algorithm> _aead_algorithm)
        : message_deserializer(_buffer_shrink_threshold),
          aead_algorithm_(std::move(_aead_algorithm)) {}

message_deserializer_confidentiality::~message_deserializer_confidentiality() = default;

message *message_deserializer_confidentiality::deserialize_message(const byte_t *_data, size_t _size) {

    if (VSOMEIP_PAYLOAD_POS > _size || !utility::is_confidentiality_level(*(_data + VSOMEIP_MESSAGE_TYPE_POS))) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(deserializer_mutex_);
    std::vector<byte_t> output;
    if (!aead_algorithm_->decipher(_data, _size, VSOMEIP_PAYLOAD_POS, output)) {
        return nullptr;
    }

    deserializer_handler handler(deserializer_);
    deserializer_->set_data(output.data(), output.size());

    length_t message_length;
    if (!deserializer_->look_ahead(VSOMEIP_LENGTH_POS_MIN, message_length)) {
        return nullptr;
    }

    update_message_type_clear(deserializer_->get_data() + VSOMEIP_MESSAGE_TYPE_POS);
    update_message_length(static_cast<length_t>(aead_algorithm_->get_deciphered_output_length(message_length)),
                          deserializer_->get_data() + VSOMEIP_LENGTH_POS_MIN);

    return deserializer_->deserialize_message();
}

bool message_deserializer_confidentiality::add_allowed_peer(crypto_instance_t _instance_id) {
    std::lock_guard<std::mutex> lock(deserializer_mutex_);
    return aead_algorithm_->add_allowed_peer(_instance_id);
}

} // namespace vsomeip
