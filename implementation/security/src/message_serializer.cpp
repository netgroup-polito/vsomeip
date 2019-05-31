// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_serializer.hpp"

#include <vsomeip/defines.hpp>
#include <vsomeip/message.hpp>
#include "../../crypto/symmetric/include/mac_algorithm.hpp"
#include "../../crypto/symmetric/include/aead_algorithm.hpp"
#include "../../logging/include/logger.hpp"
#include "../../message/include/serializer.hpp"
#include "../../utility/include/byteorder.hpp"
#include "../../utility/include/utility.hpp"

namespace vsomeip {

/**
 * A vsomeip::serializer wrapper that provides a convenient RAII-style mechanism
 * for resetting the serializer when the scoped block ends.
 */
class serializer_handler {
public:
    explicit serializer_handler(const std::unique_ptr<serializer> &_handle) : handle_(_handle) {}

    ~serializer_handler() { handle_->reset(); }

private:
    const std::unique_ptr<serializer> &handle_;
};

/**
 * Utility function that converts the _message_length value into on-wire format and
 * stores it into the byte array pointed by _data.
 *
 * @param _message_length the value to be converted.
 * @param _data the pointer of the byte array where the result is stored.
 */
static inline void update_message_length(length_t _message_length, byte_t *_data) {
    _data[0] = VSOMEIP_LONG_BYTE3(_message_length);
    _data[1] = VSOMEIP_LONG_BYTE2(_message_length);
    _data[2] = VSOMEIP_LONG_BYTE1(_message_length);
    _data[3] = VSOMEIP_LONG_BYTE0(_message_length);
}

/**
 * Modifies the value pointed by the parameter, by setting the *authentication* flag.
 */
static inline void update_message_type_authentication(byte_t *_data) {
    *_data = utility::set_authentication_flag(*_data);
}

/**
 * Modifies the value pointed by the parameter, by setting the *confidentiality* flag.
 */
static inline void update_message_type_confidentiality(byte_t *_data) {
    *_data = utility::set_confidentiality_flag(*_data);
}

/* ** MESSAGE SERIALIZER ** */

message_serializer::message_serializer(std::uint32_t _buffer_shrink_threshold)
        : serializer_(std::unique_ptr<serializer>(new serializer(_buffer_shrink_threshold))) {}

message_serializer::~message_serializer() = default;

/* ** MESSAGE SERIALIZER NOSEC ** */

message_serializer_nosec::message_serializer_nosec(std::uint32_t _buffer_shrink_threshold)
        : message_serializer(_buffer_shrink_threshold) {}

message_serializer_nosec::~message_serializer_nosec() = default;

bool message_serializer_nosec::serialize_message(const message *_message,
                                                 std::vector<byte_t> &_output) {

    std::lock_guard<std::mutex> lock(serializer_mutex_);
    serializer_handler handler(serializer_);

    if (!serializer_->serialize(_message)) {
        return false;
    }

    _output.assign(serializer_->get_data(), serializer_->get_data() + serializer_->get_size());
    return true;
}

/* ** MESSAGE SERIALIZER AUTHENTICATION ** */

message_serializer_authentication::message_serializer_authentication(std::uint32_t _buffer_shrink_threshold,
                                                                     std::unique_ptr<mac_algorithm> _mac_algorithm)
        : message_serializer(_buffer_shrink_threshold),
          mac_algorithm_(std::move(_mac_algorithm)) {}

message_serializer_authentication::~message_serializer_authentication() = default;

bool message_serializer_authentication::serialize_message(const message *_message, std::vector<byte_t> &_output) {

    std::lock_guard<std::mutex> lock(serializer_mutex_);
    serializer_handler handler(serializer_);

    if (!serializer_->serialize(_message)) {
        return false;
    }

    update_message_type_authentication(serializer_->get_data() + VSOMEIP_MESSAGE_TYPE_POS);
    update_message_length(static_cast<length_t>(mac_algorithm_->get_signed_output_length(_message->get_length())),
                          serializer_->get_data() + VSOMEIP_LENGTH_POS_MIN);

    return mac_algorithm_->sign(serializer_->get_data(), serializer_->get_size(), _output);
}

/* ** MESSAGE SERIALIZER CONFIDENTIALITY ** */

message_serializer_confidentiality::message_serializer_confidentiality(std::uint32_t _buffer_shrink_threshold,
                                                                       std::unique_ptr<aead_algorithm> _aead_algorithm)
        : message_serializer(_buffer_shrink_threshold),
          mac_algorithm_(std::move(_aead_algorithm)) {}

message_serializer_confidentiality::~message_serializer_confidentiality() = default;

bool message_serializer_confidentiality::serialize_message(const message *_message, std::vector<byte_t> &_output) {

    std::lock_guard<std::mutex> lock(serializer_mutex_);
    serializer_handler handler(serializer_);

    if (!serializer_->serialize(_message)) {
        return false;
    }

    update_message_type_confidentiality(serializer_->get_data() + VSOMEIP_MESSAGE_TYPE_POS);
    update_message_length(static_cast<length_t>(mac_algorithm_->get_enciphered_output_length(_message->get_length())),
                          serializer_->get_data() + VSOMEIP_LENGTH_POS_MIN);

    return mac_algorithm_->encipher(serializer_->get_data(), serializer_->get_size(), VSOMEIP_PAYLOAD_POS, _output);
}

} // namespace vsomeip