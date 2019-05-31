// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/session_establishment.hpp"

#include <vsomeip/vsomeip.hpp>
#include "../include/session_parameters.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_private.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_public.hpp"
#include "../../crypto/random/include/random.hpp"
#include "../../logging/include/logger.hpp"
#include "../../message/include/message_header_impl.hpp"
#include "../../message/include/serializer.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../utility/include/byteorder.hpp"

namespace vsomeip {

/* ** SESSION ESTABLISHMENT MESSAGE ** */

session_establishment_message::session_establishment_message()
        : protocol_version_(protocol_version::V_1_0), asymmetric_algorithm_(), message_digest_algorithm_(),
          challenge_(), fingerprint_(), valid_(false) {
}

session_establishment_message::session_establishment_message(service_t _service, instance_t _instance, client_t _client,
                                                             interface_version_t _version, bool _reliable,
                                                             asymmetric_crypto_algorithm _asymmetric_algorithm,
                                                             const certificate_fingerprint_t &_fingerprint)
        : protocol_version_(protocol_version::V_1_0), asymmetric_algorithm_(_asymmetric_algorithm),
          message_digest_algorithm_(FINGERPRINT_DIGEST_ALGORITHM), challenge_(), fingerprint_(_fingerprint),
          valid_(false) {

    set_service(_service);
    set_instance(_instance);
    set_method(METHOD_ID);
    set_client(_client);
    set_protocol_version(VSOMEIP_PROTOCOL_VERSION);
    set_interface_version(_version);
    set_reliable(_reliable);
}

void session_establishment_message::set_payload(std::shared_ptr<payload> _payload) {
    (void) _payload;
}

length_t session_establishment_message::get_length() const {
    return message_impl::get_length() +
           4 + /* protocol_version, asymmetric_algorithm id, message_digest_id, unused */
           static_cast<length_t>(fingerprint_.size()) +
           static_cast<length_t>(challenge_.size());
}

bool session_establishment_message::serialize(serializer *_to) const {

    if (!is_valid()) {
        VSOMEIP_WARNING << "Trying to serialize an invalid session establishment message";
        return false;
    }

    uint8_t unused(0);
    return nullptr != _to && 0 == _to->get_size() &&
           message_impl::serialize(_to) &&
           _to->serialize(static_cast<uint8_t>(protocol_version_)) &&
           _to->serialize(static_cast<uint8_t>(asymmetric_algorithm_)) &&
           _to->serialize(static_cast<uint8_t>(message_digest_algorithm_)) &&
           _to->serialize(unused) &&
           _to->serialize(challenge_.data(), static_cast<uint32_t>(challenge_.size())) &&
           _to->serialize(fingerprint_.data(), static_cast<uint32_t>(fingerprint_.size()));
}

bool session_establishment_message::deserialize(deserializer *_from) {
    uint8_t tmp_version;
    uint8_t tmp_asymmetric_algorithm;
    uint8_t tmp_message_digest_algorithm;
    uint8_t unused;

    valid_ = nullptr != _from &&
             header_.deserialize(_from) &&
             METHOD_ID == get_method() &&
             _from->deserialize(tmp_version) &&
             _from->deserialize(tmp_asymmetric_algorithm) &&
             _from->deserialize(tmp_message_digest_algorithm) &&
             _from->deserialize(unused) &&
             _from->deserialize(challenge_.data(), challenge_.size()) &&
             _from->deserialize(fingerprint_.data(), challenge_.size());

    if (valid_) {
        protocol_version_ = static_cast<protocol_version>(tmp_version);
        asymmetric_algorithm_ = static_cast<asymmetric_crypto_algorithm>(tmp_asymmetric_algorithm);
        message_digest_algorithm_ = static_cast<digest_algorithm>(tmp_message_digest_algorithm);

        valid_ = protocol_version::V_1_0 == protocol_version_ &&
                 FINGERPRINT_DIGEST_ALGORITHM == message_digest_algorithm_;
    }

    return valid_;
}


asymmetric_crypto_algorithm session_establishment_message::get_asymmetric_algorithm() const {
    return asymmetric_algorithm_;
}

const session_establishment_message::challenge_t &session_establishment_message::get_challenge() const {
    return challenge_;
}

const certificate_fingerprint_t &session_establishment_message::get_fingerprint() const {
    return fingerprint_;
}

bool session_establishment_message::is_valid() const {
    return valid_;
}

/* ** SESSION ESTABLISHMENT REQUEST ** */

session_establishment_request::session_establishment_request(service_t _service, instance_t _instance, client_t _client,
                                                             interface_version_t _version, bool _reliable,
                                                             asymmetric_crypto_algorithm _asymmetric_algorithm,
                                                             const certificate_fingerprint_t &_fingerprint,
                                                             random &_random)
        : session_establishment_message(_service, _instance, _client, _version,
                                        _reliable, _asymmetric_algorithm, _fingerprint) {

    set_message_type(message_type_e::MT_REQUEST);
    set_return_code(return_code_e::E_OK);
    valid_ = _random.randomize(challenge_.data(), challenge_.size());
}

/* ** SESSION ESTABLISHMENT RESPONSE ** */

session_establishment_response::session_establishment_response(uint32_t _buffer_shrink_threshold)
    : security_level_(security_level::SL_INVALID), buffer_shrink_threshold_(_buffer_shrink_threshold) {
}

session_establishment_response::session_establishment_response(const session_establishment_request &_request,
                                                               const certificate_fingerprint_t &_fingerprint,
                                                               const std::shared_ptr<session_parameters> &_session_parameters,
                                                               std::shared_ptr<asymmetric_crypto_private> _own_private_key,
                                                               std::shared_ptr<asymmetric_crypto_public> _peer_public_key)

        : session_establishment_message(_request.get_service(), _request.get_instance(), _request.get_client(),
                                        _request.get_interface_version(), _request.is_reliable(),
                                        _request.get_asymmetric_algorithm(), _fingerprint),
          security_level_(_session_parameters ? _session_parameters->get_security_level() : security_level::SL_INVALID),
          session_parameters_(_session_parameters),
          private_key_(std::move(_own_private_key)),
          public_key_(std::move(_peer_public_key)),
          buffer_shrink_threshold_(0) {

    challenge_ = _request.get_challenge();
    valid_ = _request.is_valid() && nullptr != session_parameters_ &&
             session_parameters_->is_valid() && session_parameters_->is_provider();
    set_session(_request.get_session());
    set_message_type(message_type_e::MT_RESPONSE);
    set_return_code(return_code_e::E_OK);
}

length_t session_establishment_response::get_length() const {
    return session_establishment_message::get_length() +
           2 + /* symmetric algorithm id */
           static_cast<length_t>(sizeof(crypto_instance_t)) /* instance id */;
}

bool session_establishment_response::serialize(serializer *_to) const {

    crypto_instance_t instance_id;
    bool success = session_establishment_message::serialize(_to) &&
                   _to->serialize(static_cast<uint8_t>(session_parameters_->get_security_level())) &&
                   _to->serialize(static_cast<uint8_t>(session_parameters_->get_crypto_algorithm())) &&
                   session_parameters::INVALID_INSTANCE_ID !=
                        (instance_id = session_parameters_->get_next_instance_id()) &&
                   _to->serialize(instance_id);

    if (!success) {
        return false;
    }

    auto encrypted_symmetric_key = session_parameters_->get_encrypted_key(public_key_);
    auto signature_length = static_cast<uint16_t>(private_key_->get_signature_length(_to->get_size()));
    success = !encrypted_symmetric_key.empty() &&
              _to->serialize(static_cast<uint16_t>(encrypted_symmetric_key.size())) &&
              _to->serialize(encrypted_symmetric_key) &&
              _to->serialize(signature_length);

    if (!success) {
        return false;
    }

    length_t length = get_length() +
                      static_cast<length_t>(sizeof(uint16_t) + encrypted_symmetric_key.size()) +
                      static_cast<length_t>(sizeof(signature_length) + signature_length);

    // Adapt the message length
    *(_to->get_data() + VSOMEIP_LENGTH_POS_MIN + 0) = VSOMEIP_LONG_BYTE3(length);
    *(_to->get_data() + VSOMEIP_LENGTH_POS_MIN + 1) = VSOMEIP_LONG_BYTE2(length);
    *(_to->get_data() + VSOMEIP_LENGTH_POS_MIN + 2) = VSOMEIP_LONG_BYTE1(length);
    *(_to->get_data() + VSOMEIP_LENGTH_POS_MIN + 3) = VSOMEIP_LONG_BYTE0(length);

    std::vector<byte_t> digital_signature;
    success = private_key_->sign(_to->get_data(), _to->get_size(), digital_signature) &&
              _to->serialize(digital_signature);

    return success;
}

bool session_establishment_response::deserialize_base(deserializer *_from) {

    uint8_t tmp_security_level;
    valid_ = session_establishment_message::deserialize(_from) &&
             _from->deserialize(tmp_security_level);

    if (valid_) {
        security_level_ = static_cast<security_level>(tmp_security_level);
    }
    return valid_;
}

bool session_establishment_response::deserialize(deserializer *_from) {

    uint8_t tmp_crypto_algorithm;
    uint16_t encrypted_key_length, signature_length;
    crypto_instance_t crypto_instance_id;

    valid_ = valid_ && nullptr != _from &&
             _from->deserialize(tmp_crypto_algorithm) &&
             _from->deserialize(crypto_instance_id) &&
             _from->deserialize(encrypted_key_length);

    if (!valid_) {
        return false;
    }

    crypto_algorithm_packed symmetric_algorithm = {
            security_level_, static_cast<crypto_algorithm>(tmp_crypto_algorithm)
    };
    std::vector<byte_t> encrypted_symmetric_key;
    encrypted_symmetric_key.reserve(encrypted_key_length);

    valid_ = _from->deserialize(encrypted_symmetric_key) &&
             _from->deserialize(signature_length) &&
             _from->get_remaining() == signature_length;

    if (!valid_) {
        return false;
    }

    auto data_begin = _from->get_data();
    auto data_length = _from->get_available() - signature_length;
    auto signature_begin = data_begin + data_length;

    valid_ = public_key_->verify(data_begin, data_length, signature_begin, signature_length);

    if (!valid_) {
        return false;
    }

    session_parameters_ = std::make_shared<session_parameters>(symmetric_algorithm, encrypted_symmetric_key,
                                                               static_cast<crypto_instance_t>(crypto_instance_id),
                                                               private_key_, buffer_shrink_threshold_);
    return session_parameters_->is_valid();
}

void session_establishment_response::set_crypto_material(std::shared_ptr<asymmetric_crypto_private> _own_private_key,
                                                         std::shared_ptr<asymmetric_crypto_public> _peer_public_key) {
    private_key_ = std::move(_own_private_key);
    public_key_ = std::move(_peer_public_key);
}

security_level session_establishment_response::get_security_level() const {
    return security_level_;
}

std::shared_ptr<session_parameters> session_establishment_response::get_session_parameters() const {
    return session_parameters_;
}

bool session_establishment_response::is_valid() const {
    return session_establishment_message::is_valid() && is_valid_crypto_material();
}

bool session_establishment_response::is_valid_crypto_material() const {
    return nullptr != private_key_ && private_key_->is_valid() &&
           nullptr != public_key_ && public_key_->is_valid();
}

} // namespace vsomeip
