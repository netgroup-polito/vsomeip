// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_DESERIALIZER_HPP
#define VSOMEIP_MESSAGE_DESERIALIZER_HPP

#include <memory>
#include <mutex>
#include <vector>

#include <vsomeip/primitive_types.hpp>
#include "../../crypto/common/include/crypto_types.hpp"

namespace vsomeip {

class message;
class deserializer;
class mac_algorithm;
class aead_algorithm;

/* ** MESSAGE DESERIALIZER ** */

/**
 * \brief Base class to implement message deserializers.
 *
 * This abstract class provides a wrapper around a deserializer, which constructs a
 * vsomeip::message object from the on-wire format. A different specialization is
 * implemented for each security level, encapsulating the necessary cryptographic
 * objects and providing the requested security guarantees during the deserialization.
 */
class message_deserializer {
public:
    virtual ~message_deserializer();

    /**
     * \brief Constructs a SOME/IP message from raw data read from the network.
     *
     * This function abstracts the deserialization process, constructing a SOME/IP
     * message from the on-wire format and verifying the requested cryptographic
     * protections. Actual implementations are expected to be thread-safe, by
     * using a mutex object for synchronization purposes during the processing.
     *
     * @param _data the pointer to the data received from the network.
     * @param _size the size of the data received from the network.
     * @return the constructed vsomeip::message object or nullptr in case of error.
     */
    virtual message *deserialize_message(const byte_t *_data, size_t _size) = 0;

    /**
     * \brief Stores a new allowed communication peer.
     *
     * This function adds the specified instance ID to the set of the allowed peers
     * for the current communication, which is checked for replay protection in case
     * of services operating at *authentication* and *confidentiality* level.
     *
     * @param _instance_id the ID to be added.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool add_allowed_peer(crypto_instance_t _instance_id) = 0;

protected:
    explicit message_deserializer(std::uint32_t _buffer_shrink_threshold);

protected:
    std::mutex deserializer_mutex_;
    std::unique_ptr<deserializer> deserializer_;
};

/* ** MESSAGE DESERIALIZER NOSEC ** */

/**
 * \brief message_deserializer specialization for services operating at *nosec* level.
 *
 * This class provides an implementation of the message_deserializer interface suitable
 * for services operating at *nosec* level. Being them characterized by no security
 * properties, it implements only the deserialization part of the process, without further
 * actions.
 */
class message_deserializer_nosec : public message_deserializer {
public:
    explicit message_deserializer_nosec(std::uint32_t _buffer_shrink_threshold);

    ~message_deserializer_nosec() override;

    message *deserialize_message(const byte_t *_data, size_t _size) override;

    bool add_allowed_peer(crypto_instance_t _instance_id) override;
};

/* ** MESSAGE DESERIALIZER AUTHENTICATION ** */

/**
 * \brief message_deserializer specialization for services operating at *authentication* level.
 *
 * This class provides an implementation of the message_deserializer interface suitable
 * for services operating at *authentication* level. *Authentication*-level messages are
 * deserialized through a two-phase process: the appended Message Authentication Code is
 * initially verified (through the vsomeip::MAC_algorithm object associated to the session)
 * and, only in case of legit messages, the deserialized vsomeip::message object is constructed
 * and returned.
 */
class message_deserializer_authentication : public message_deserializer {
public:
    message_deserializer_authentication(std::uint32_t _buffer_shrink_threshold,
                                        std::unique_ptr<mac_algorithm> _mac_algorithm);

    ~message_deserializer_authentication() override;

    message *deserialize_message(const byte_t *_data, size_t _size) override;

    bool add_allowed_peer(crypto_instance_t _instance_id) override;

private:
    std::unique_ptr<mac_algorithm> mac_algorithm_;
};

/* ** MESSAGE DESERIALIZER CONFIDENTIALITY ** */

/**
 * \brief message_deserializer specialization for services operating at *confidentiality* level.
 *
 * This class provides an implementation of the message_deserializer interface suitable
 * for services operating at *confidentiality* level. *Confidentiality*-level messages are
 * deserialized through a two-phase process: the appended Message Authentication Code is
 * initially verified (through the vsomeip::cipher object associated to the session, which
 * also deciphers the payload) and, only in case of legit messages, the deserialized
 * vsomeip::message object is constructed and returned.
 */
class message_deserializer_confidentiality : public message_deserializer {
public:
    message_deserializer_confidentiality(std::uint32_t _buffer_shrink_threshold,
                                         std::unique_ptr<aead_algorithm> _aead_algorithm);

    ~message_deserializer_confidentiality() override;

    message *deserialize_message(const byte_t *_data, size_t _size) override;

    bool add_allowed_peer(crypto_instance_t _instance_id) override;

private:
    std::unique_ptr<aead_algorithm> aead_algorithm_;
};

} // namespace vsomeip

#endif //VSOMEIP_MESSAGE_DESERIALIZER_HPP
