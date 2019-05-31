// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SESSION_PARAMETERS_HPP
#define VSOMEIP_SESSION_PARAMETERS_HPP

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include <vsomeip/primitive_types.hpp>
#include "../../crypto/common/include/algorithms.hpp"
#include "../../crypto/common/include/crypto_types.hpp"

namespace vsomeip {

class asymmetric_crypto_private;
class asymmetric_crypto_public;
class message_serializer;
class message_deserializer;
class mac_algorithm;
class aead_algorithm;
class random;

/**
 * \brief Encapsulates the parameters associated to a secure session.
 *
 * This class stores the different elements that characterize a secure session
 * and provides the necessary methods to interact with them. The main parameters
 * include the security level at which the service operates, the chosen symmetric
 * algorithm together with the associated key and the vsomeip::message_serializer
 * and vsomeip::message_deserializer objects used to convert messages to and
 * from the on-wire format while applying at the same time the requested protections.
 */
class session_parameters {

public:
    /// \brief The instance number which identifies the provider of the service.
    static const crypto_instance_t PROVIDER_INSTANCE_ID = 0;
    /// \brief The number which identifies an invalid instance, used to signal errors.
    static const crypto_instance_t INVALID_INSTANCE_ID = std::numeric_limits<crypto_instance_t>::max();

public:
    /**
     * \brief Constructs a new session_parameter object.
     *
     * This constructor creates a new object associated to the provider of a service,
     * by generating a new random symmetric key according to the security level and
     * algorithm specified as parameter. In case an error occurs during the generation,
     * the valid_ flag is set to false.
     *
     * @param _algorithm_packed the security level and algorithm associated to the session.
     * @param _random the object abstracting the random generator concept.
     * @param _buffer_shrink_threshold requested to initialize plain vsomeip::serializer
     *                                 and vsomeip::deserializer object.
     */
    session_parameters(crypto_algorithm_packed _algorithm_packed, random &_random,
                       std::uint32_t _buffer_shrink_threshold);

    /**
     * \brief Constructs a new session_parameter object.
     *
     * This constructor creates a new object associated to a requester of a service,
     * by extracting the necessary symmetric key from the encrypted blob received
     * within a vsomeip::session_establishment_response.
     *
     * @param _algorithm_packed the security level and algorithm associated to the session.
     * @param _encrypted_key the encrypted symmetric key transmitted by the provider.
     * @param _instance_id the instance ID associated by the provided to the requester under examination.
     * @param _private_key the object wrapping the private key used to decipher the symmetric one.
     * @param _buffer_shrink_threshold requested to initialize plain vsomeip::serializer
     *                                 and vsomeip::deserializer object.
     */
    session_parameters(crypto_algorithm_packed _algorithm_packed, const std::vector<byte_t> &_encrypted_key,
                       crypto_instance_t _instance_id, const std::shared_ptr<asymmetric_crypto_private> &_private_key,
                       uint32_t _buffer_shrink_threshold);

    session_parameters(const session_parameters &) = delete;

    session_parameters &operator=(const session_parameters &) = delete;

    /// \brief Returns the security level associated to the session.
    security_level get_security_level() const;

    /// \brief Returns the symmetric cryptographic algorithm associated to the session.
    crypto_algorithm get_crypto_algorithm() const;

    /// \brief Returns the vsomeip::message_serializer associated to the session.
    const std::shared_ptr<message_serializer> &get_serializer() const;

    /// \biref Returns the vsomeip::message_deserializer associated to the session.
    const std::shared_ptr<message_deserializer> &get_deserializer() const;

    /**
     * \brief Returns the next instance ID to be assigned to a requester, in case
     * the object represents a provider, and INVALID_INSTANCE_ID otherwise.
     */
    crypto_instance_t get_next_instance_id();

    /**
     * \brief Returns the symmetric key in encrypted form.
     *
     * The symmetric key necessary for the actual communication is encrypted
     * by using the public key contained in the object specified as parameter.
     * In case the current instance does not represent the provider of the
     * service or an error occurs, an empty vector is returned.
     */
    std::vector<byte_t> get_encrypted_key(const std::shared_ptr<asymmetric_crypto_public> &_peer_public_key) const;

    /// \brief Returns whether the object is associated to the service provider or not.
    bool is_provider() const;

    /// \brief Returns whether the object has been correctly constructed or not.
    bool is_valid() const;

private:
    /**
     * \brief Returns a brand-new vsomeip::mac_algorithm object created according
     * to the specified symmetric algorithm and embedding the associated key.
     */
    std::unique_ptr<mac_algorithm> get_mac_algorithm() const;

    /**
     * \brief Returns a brand-new vsomeip::aead_algorithm object created according
     * to the specified symmetric algorithm and embedding the associated key.
     */
    std::unique_ptr<aead_algorithm> get_aead_algorithm() const;

    /**
     * \brief Creates and initializes the vsomeip::message_serializer and
     * vsomeip::message_deserializer objects according to the parameters
     * associated to the session.
     */
    bool initialize_serializers(uint32_t _buffer_shrink_threshold);

private:
    const crypto_algorithm_packed algorithm_packed_;
    const secure_vector<byte_t> key_;
    const crypto_instance_t instance_id_;

    std::mutex next_instance_id_mutex_;
    crypto_instance_t next_instance_id_;

    std::shared_ptr<message_serializer> serializer_;
    std::shared_ptr<message_deserializer> deserializer_;

    const bool valid_;
};

} // namespace vsomeip


#endif //VSOMEIP_SESSION_PARAMETERS_HPP
