// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/session_parameters.hpp"

#include "../include/message_serializer.hpp"
#include "../include/message_deserializer.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_private.hpp"
#include "../../crypto/asymmetric/include/asymmetric_crypto_public.hpp"
#include "../../crypto/random/include/random.hpp"
#include "../../crypto/symmetric/include/aes_ccm.hpp"
#include "../../crypto/symmetric/include/aes_gcm.hpp"
#include "../../crypto/symmetric/include/chacha20_poly1305.hpp"

namespace vsomeip {

static size_t get_key_length(crypto_algorithm _algorithm) {
    switch (_algorithm) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return chacha20_poly1305::KEY_LENGTH;

        case crypto_algorithm::CA_AES_GCM_128:
            return aes_gcm<aes_key_length::AES_128>::KEY_LENGTH;
        case crypto_algorithm::CA_AES_GCM_256:
            return aes_gcm<aes_key_length::AES_256>::KEY_LENGTH;

        case crypto_algorithm::CA_AES_CCM_128:
            return aes_ccm<aes_key_length::AES_128>::KEY_LENGTH;
        case crypto_algorithm::CA_AES_CCM_256:
            return aes_ccm<aes_key_length::AES_256>::KEY_LENGTH;

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return 0;
    }
    return 0;
}

session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed, random &_random,
                                       std::uint32_t _buffer_shrink_threshold)
        : algorithm_packed_(_algorithm_packed),
          key_(_random.randomize(get_key_length(get_crypto_algorithm()))),
          instance_id_(PROVIDER_INSTANCE_ID), next_instance_id_(PROVIDER_INSTANCE_ID + 1),
          valid_(_algorithm_packed.is_valid_combination() &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
}

session_parameters::session_parameters(crypto_algorithm_packed _algorithm_packed,
                                       const std::vector<byte_t> &_encrypted_key,
                                       crypto_instance_t _instance_id,
                                       const std::shared_ptr<asymmetric_crypto_private> &_private_key,
                                       uint32_t _buffer_shrink_threshold)
        : algorithm_packed_(_algorithm_packed),
          key_(_private_key && security_level::SL_NOSEC != get_security_level()
               ? _private_key->decipher(_encrypted_key.data(), _encrypted_key.size())
               : secure_vector<byte_t>()),
          instance_id_(_instance_id),
          valid_(_algorithm_packed.is_valid_combination() && PROVIDER_INSTANCE_ID != _instance_id &&
                 (security_level::SL_NOSEC == get_security_level() || !key_.empty()) &&
                 initialize_serializers(_buffer_shrink_threshold) &&
                 deserializer_->add_allowed_peer(PROVIDER_INSTANCE_ID)) {
}

security_level session_parameters::get_security_level() const {
    return algorithm_packed_.security_level_;
}

crypto_algorithm session_parameters::get_crypto_algorithm() const {
    return algorithm_packed_.crypto_algorithm_;
}

const std::shared_ptr<message_serializer> &session_parameters::get_serializer() const {
    return serializer_;
}

const std::shared_ptr<message_deserializer> &session_parameters::get_deserializer() const {
    return deserializer_;
}


crypto_instance_t session_parameters::get_next_instance_id() {
    std::lock_guard<std::mutex> its_mutex(next_instance_id_mutex_);
    if (is_provider() && is_valid() && INVALID_INSTANCE_ID != next_instance_id_) {
        deserializer_->add_allowed_peer(next_instance_id_);
        return next_instance_id_++;
    }

    return INVALID_INSTANCE_ID;
}

std::vector<byte_t>
session_parameters::get_encrypted_key(const std::shared_ptr<asymmetric_crypto_public> &_peer_public_key) const {

    std::vector<byte_t> encrypted_key;
    if (is_provider() && is_valid() && _peer_public_key) {
        _peer_public_key->encipher(key_.data(), key_.size(), encrypted_key);
    }
    return encrypted_key;
}

bool session_parameters::is_provider() const {
    return PROVIDER_INSTANCE_ID == instance_id_;
}

bool session_parameters::is_valid() const {
    return valid_;
}

std::unique_ptr<mac_algorithm> session_parameters::get_mac_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<mac_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<mac_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<mac_algorithm>();
    }
    return std::unique_ptr<mac_algorithm>();
}

std::unique_ptr<aead_algorithm> session_parameters::get_aead_algorithm() const {
    switch (get_crypto_algorithm()) {
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return std::unique_ptr<aead_algorithm>(new chacha20_poly1305(key_, instance_id_));

        case crypto_algorithm::CA_AES_GCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_GCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_gcm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_AES_CCM_128:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_128>(key_, instance_id_));
        case crypto_algorithm::CA_AES_CCM_256:
            return std::unique_ptr<aead_algorithm>(new aes_ccm<aes_key_length::AES_256>(key_, instance_id_));

        case crypto_algorithm::CA_INVALID:
        case crypto_algorithm::CA_NULL:
            return std::unique_ptr<aead_algorithm>();
    }
    return std::unique_ptr<aead_algorithm>();
}

bool session_parameters::initialize_serializers(uint32_t _buffer_shrink_threshold) {

    switch (get_security_level()) {
        case security_level::SL_NOSEC: {
            serializer_ = std::make_shared<message_serializer_nosec>(_buffer_shrink_threshold);
            deserializer_ = std::make_shared<message_deserializer_nosec>(_buffer_shrink_threshold);
            return true;
        }

        case security_level::SL_AUTHENTICATION: {
            auto serializer_algorithm = get_mac_algorithm();
            auto deserializer_algorithm = get_mac_algorithm();

            if (!serializer_algorithm || !deserializer_algorithm) {
                return false;
            }

            serializer_ = std::make_shared<message_serializer_authentication>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm));
            deserializer_ = std::make_shared<message_deserializer_authentication>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_CONFIDENTIALITY: {
            auto serializer_algorithm = get_aead_algorithm();
            auto deserializer_algorithm = get_aead_algorithm();

            if (!serializer_algorithm || !deserializer_algorithm) {
                return false;
            }

            serializer_ = std::make_shared<message_serializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(serializer_algorithm));
            deserializer_ = std::make_shared<message_deserializer_confidentiality>(
                    _buffer_shrink_threshold, std::move(deserializer_algorithm));
            return true;
        }

        case security_level::SL_INVALID: {
            return false;
        }
    }

    return false;
}

} // namespace vsomeip
