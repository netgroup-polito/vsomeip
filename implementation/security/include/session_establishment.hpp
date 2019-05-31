// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SESSION_ESTABLISHMENT_HPP
#define VSOMEIP_SESSION_ESTABLISHMENT_HPP

#include <array>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/payload.hpp>

#include "../../crypto/common/include/algorithms.hpp"
#include "../../crypto/common/include/crypto_types.hpp"
#include "../../message/include/message_impl.hpp"

namespace vsomeip {

class asymmetric_crypto_private;
class asymmetric_crypto_public;
class random;
class session_parameters;

/* ** SESSION ESTABLISHMENT MESSAGE ** */

/**
 * \brief Base class to implement session establishment messages.
 *
 * The session establishment phase is a simple unicast protocol made up
 * of two message exchanges: a request sent by a requester towards the
 * provider of the service and the corresponding response, travelling in
 * the opposite direction.
 *
 * This abstract class represents the initial fields of session establishment
 * messages, which are common to both requests and responses. Additionally,
 * it also implements the serialize and deserialize methods for the involved
 * information as well as accessor getter functions.
 */
class session_establishment_message : public message_impl {

public:
    /// \brief The method ID associated to the session establishment process.
    static const method_t METHOD_ID = 0x7fff;

    /// brief The digest algorithm used to compute certificate fingerprints.
    static const digest_algorithm FINGERPRINT_DIGEST_ALGORITHM = digest_algorithm::MD_SHA256;

    /// \brief The length in bytes of the challenge field.
    static const length_t CHALLENGE_LENGTH = 32;
    /// \brief The data type used to store the challenge content.
    using challenge_t = std::array<byte_t, CHALLENGE_LENGTH>;

    /// \brief The enumeration of possible values for the protocol version field.
    enum class protocol_version : uint8_t {
        V_1_0 = 0x10 ///< \brief Version 1.0
    };

public:
    ~session_establishment_message() override = default;

    /// \brief Part of the vsomeip::message interface but not implemented.
    void set_payload(std::shared_ptr<payload> _payload) override;

    /**
     * \brief Returns the length of the session establishment message.
     *
     * The returned value does not comprise the SOME/IP header.
     */
    length_t get_length() const override;

    /// \brief Serializes the content of the session establishment message.
    bool serialize(serializer *_to) const override;

    /// \brief Deserializes the content of the session establishment message.
    bool deserialize(deserializer *_from) override;

    /// \brief Returns the asymmetric algorithm from the session establishment message.
    asymmetric_crypto_algorithm get_asymmetric_algorithm() const;

    /// \brief Returns the challenge value from the session establishment message.
    const challenge_t &get_challenge() const;

    /// \brief Returns the fingerprint value from the session establishment message.
    const certificate_fingerprint_t &get_fingerprint() const;

    /// \brief Returns whether the object has been correctly initialized or not.
    virtual bool is_valid() const;

protected:
    /// \brief Constructs a new session_establishment_message object.
    session_establishment_message();

    /**
     * \brief Constructs a new session_establishment_message object.
     *
     * @param _service the identifier of the target service.
     * @param _instance the identifier of the target service instance.
     * @param _client the identifier of the client issuing the request.
     * @param _version the interface version in the SOME/IP message header.
     * @param _reliable whether the message is transported using TCP or UDP.
     * @param _asymmetric_algorithm the identifier of the asymmetric algorithm used for the authentication.
     * @param _fingerprint the fingerprint of the digital certificate associated to the current application.
     */
    session_establishment_message(service_t _service, instance_t _instance, client_t _client,
                                  interface_version_t _version, bool _reliable,
                                  asymmetric_crypto_algorithm _asymmetric_algorithm,
                                  const certificate_fingerprint_t &_fingerprint);

protected:
    protocol_version protocol_version_;
    asymmetric_crypto_algorithm asymmetric_algorithm_;
    digest_algorithm message_digest_algorithm_;

    challenge_t challenge_;
    certificate_fingerprint_t fingerprint_;

    bool valid_;
};

/* ** SESSION ESTABLISHMENT REQUEST ** */

/**
 * \brief This class represents a session establishment request.
 */
class session_establishment_request : public session_establishment_message {

public:
    /// \brief Constructs a new session_establishment_request object.
    session_establishment_request() = default;

    /**
     * \brief Constructs a new session_establishment_request object.
     *
     * @param _service the identifier of the target service.
     * @param _instance the identifier of the target service instance.
     * @param _client the identifier of the client issuing the request.
     * @param _version the interface version in the SOME/IP message header.
     * @param _reliable whether the message is transported using TCP or UDP.
     * @param _asymmetric_algorithm the identifier of the asymmetric algorithm used for the authentication.
     * @param _fingerprint the fingerprint of the digital certificate associated to the current application.
     * @param _random the object abstracting the random generator concept.
     */
    session_establishment_request(service_t _service, instance_t _instance, client_t _client,
                                  interface_version_t _version, bool _reliable,
                                  asymmetric_crypto_algorithm _asymmetric_algorithm,
                                  const certificate_fingerprint_t &_fingerprint,
                                  random &_random);

    ~session_establishment_request() override = default;
};

/* ** SESSION ESTABLISHMENT RESPONSE ** */

/**
 * \brief This class represents a session establishment response.
 *
 * The deserialization process for a session establishment response
 * is different from the other cases since it is composed by two phases.
 * Initially, the deserialize_base method must be invoked, to extract
 * the values from the initial fields of the message and, in particular,
 * to get the the certificate fingerprint of the peer and the security
 * level at which the service operates. Once its public key has been
 * retrieved, it can be specified, along with the private key associated
 * to the current application, through the set_crypto_material function
 * and finally proceed with the complete deserialization.
 */
class session_establishment_response : public session_establishment_message {

public:
    /// \brief Constructs a new session_establishment_response object.
    explicit session_establishment_response(uint32_t _buffer_shrink_threshold);

    /**
     * \brief Constructs a new session_establishment_response object.
     *
     * @param _request the session establishment request from which this response is contructed.
     * @param _fingerprint the fingerprint of the digital certificate associated to the current application.
     * @param _session_parameters the object containing the parameters associated to the current session.
     * @param _own_private_key the object representing the private key associated to the current
     * application, necessary to sign the response message.
     * @param _peer_public_key the object representing the public key associated to the requester
     * of the service, necessary to encrypt the symmetric key.
     */
    session_establishment_response(const session_establishment_request &_request,
                                   const certificate_fingerprint_t &_fingerprint,
                                   const std::shared_ptr<session_parameters> &_session_parameters,
                                   std::shared_ptr<asymmetric_crypto_private> _own_private_key,
                                   std::shared_ptr<asymmetric_crypto_public> _peer_public_key);

    ~session_establishment_response() override = default;

    /**
     * \brief Returns the length of the session establishment response.
     *
     * The returned value does not comprise the SOME/IP header and the elements
     * computed only during the serialization process -- the encrypted key and the
     * digital signature.
     */
    length_t get_length() const override;

    /**
     * \brief Serializes the content of the session establishment response.
     *
     * Additionally, it encrypts the symmetric key part of the session
     * parameters by using the public key of the requester, to prevent
     * access from malicious parties. Moreover, a digital signature
     * covering the whole message is computed by using the private key
     * associated to the current application, to guarantee its authenticity
     * and integrity.
     */
    bool serialize(serializer *_to) const override;

    /// \brief Performs the deserialization of the initial fields of the response.
    bool deserialize_base(deserializer *_from);

    /**
     * \brief Completes the message deserialization.
     *
     * It requires the previous execution of deserialize_base and set_crypto_material.
     */
    bool deserialize(deserializer *_from) override;

    /**
     * \brief Specifies the cryptographic material necessary to complete the deserialization
     * of the message.
     *
     * @param _own_private_key the object representing the private key associated to the
     * current application, necessary to decipher the symmetric key.
     * @param _peer_public_key the object representing the public key associated to the
     * provider of the service, necessary to verify its digital signature.
     */
    void set_crypto_material(std::shared_ptr<asymmetric_crypto_private> _own_private_key,
                             std::shared_ptr<asymmetric_crypto_public> _peer_public_key);

    /// \brief Returns the security level from the session establishment response.
    security_level get_security_level() const;

    /**
     * \brief Returns the session parameters obtained from the session establishment response
     * or nullptr in case of failure (the object state is invalid).
     */
    std::shared_ptr<session_parameters> get_session_parameters() const;

    /// \brief Returns whether the object has been correctly initialized or not.
    bool is_valid() const override;

private:
    bool is_valid_crypto_material() const;

private:
    security_level security_level_;
    std::shared_ptr<session_parameters> session_parameters_;

    std::shared_ptr<asymmetric_crypto_private> private_key_;
    std::shared_ptr<asymmetric_crypto_public> public_key_;

    const uint32_t buffer_shrink_threshold_;
};

} // namespace vsomeip


#endif //VSOMEIP_SESSION_ESTABLISHMENT_HPP
