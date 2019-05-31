// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_MESSAGE_SERIALIZER_HPP
#define VSOMEIP_MESSAGE_SERIALIZER_HPP

#include <memory>
#include <mutex>
#include <vector>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip {

class message;
class serializer;
class mac_algorithm;
class aead_algorithm;

/* ** MESSAGE SERIALIZER ** */

/**
 * \brief Base class to implement message serializers.
 *
 * This abstract class provides a wrapper around a serializer, which converts
 * a vsomeip::message object into the on-wire format. A different specialization
 * is implemented for each security level, encapsulating the necessary
 * cryptographic objects and providing the requested security guarantees to
 * the serialized data.
 */
class message_serializer {
public:
    virtual ~message_serializer();

    /**
     * \brief Converts a SOME/IP message into raw data ready to be transmitted.
     *
     * This function abstracts the serialization process, converting a SOME/IP
     * message into the on-wire format and applying the requested cryptographic
     * protections. Actual implementations are expected to be thread-safe, by
     * using a mutex object for synchronization purposes during the processing.
     *
     * @param _message the pointer to the vsomeip::message object that needs to be processed.
     * @param _output the array of bytes where the result is stored.
     * @return a value indicating whether the operation succeeded or not.
     */
    virtual bool serialize_message(const message *_message, std::vector<byte_t> &_output) = 0;

protected:
    explicit message_serializer(std::uint32_t _buffer_shrink_threshold);

protected:
    std::mutex serializer_mutex_;
    std::unique_ptr<serializer> serializer_;
};

/* ** MESSAGE SERIALIZER NOSEC ** */

/**
 * \brief message_serializer specialization for services operating at *nosec* level.
 *
 * This class provides an implementation of the message_serializer interface suitable
 * for services operating at *nosec* level. Being them characterized by no security
 * properties, it implements only the serialization part of the process, without further
 * actions.
 */
class message_serializer_nosec : public message_serializer {
public:
    explicit message_serializer_nosec(std::uint32_t _buffer_shrink_threshold);

    ~message_serializer_nosec() override;

    bool serialize_message(const vsomeip::message *_message, std::vector<byte_t> &_output) override;
};

/* ** MESSAGE SERIALIZER AUTHENTICATION ** */

/**
 * \brief message_serializer specialization for services operating at *authentication* level.
 *
 * This class provides an implementation of the message_serializer interface suitable
 * for services operating at *authentication* level. *Authentication*-level messages are
 * serialized through a two-phase process: after having converted a SOME/IP packet into
 * the on-wire format, the obtained stream of bytes is processed through a Message
 * Authentication Code algorithm (abstracted by a vsomeip::mac_algorithm object) to compute a
 * *signature* that is appended at the end of the stream, together with the support data
 * necessary for verification.
 */
class message_serializer_authentication : public message_serializer {
public:
    message_serializer_authentication(std::uint32_t _buffer_shrink_threshold,
                                      std::unique_ptr<mac_algorithm> _mac_algorithm);

    ~message_serializer_authentication() override;

    bool serialize_message(const vsomeip::message *_message, std::vector<byte_t> &_output) override;

private:
    std::unique_ptr<mac_algorithm> mac_algorithm_;
};

/* ** MESSAGE SERIALIZER CONFIDENTIALITY ** */

/**
 * \brief message_serializer specialization for services operating at *confidentiality* level.
 *
 * This class provides an implementation of the message_serializer interface suitable
 * for services operating at *confidentiality* level. *Confidentiality*-level messages are
 * serialized through a two-phase process: after having converted a SOME/IP packet into
 * the on-wire format, the obtained stream of bytes is processed through an Authenticated
 * Encryption algorithm (abstracted by a vsomeip::aead_algorithm object) to both encrypt the payload
 * and compute a *signature* that is appended at the end of the stream, together with
 * the support data necessary for verification and decryption.
 */
class message_serializer_confidentiality : public message_serializer {
public:
    message_serializer_confidentiality(std::uint32_t _buffer_shrink_threshold,
                                       std::unique_ptr<aead_algorithm> _aead_algorithm);

    ~message_serializer_confidentiality() override;

    bool serialize_message(const vsomeip::message *_message, std::vector<byte_t> &_output) override;

private:
    std::unique_ptr<aead_algorithm> mac_algorithm_;
};

} // namespace vsomeip

#endif //VSOMEIP_MESSAGE_SERIALIZER_HPP
