// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_DIGITAL_CERTIFICATE_HPP
#define VSOMEIP_DIGITAL_CERTIFICATE_HPP

#include <memory>

#include <vsomeip/primitive_types.hpp>
#include "../../common/include/algorithms.hpp"
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

class asymmetric_crypto_public;

/**
 * \brief Interface representing an Asymmetric Cryptography Public Certificate.
 *
 * This class provides an abstraction of a public certificate, allowing the
 * extraction of the information therein contained. It is exploited to allow
 * an easy replacement of one implementation with another, granting the final
 * users the capability to choose the most suitable algorithm through configurations.
 * The actual implementations of this interface are required to be thread-safe,
 * so that the concurrent execution of the different methods is safe.
 */
class digital_certificate {

public:
    virtual ~digital_certificate() = default;

    /// \brief Returns whether the current instance has been correctly initialized or not.
    virtual bool is_valid() = 0;

    /// \brief Returns the public key stored within the certificate.
    virtual std::shared_ptr<asymmetric_crypto_public> get_public_key() = 0;

    /// \brief Returns the fingerprint associated to the certificate.
    virtual const certificate_fingerprint_t & get_fingerprint() = 0;

    /**
     * \brief Looks-up the minimum security level that needs to be guaranteed
     * for the specified service.
     *
     * @param _service the ID of the service.
     * @param _instance the ID of the service instance.
     * @param _provider a value indicating whether the application is offering
     * or requesting the service.
     * @return the minimum security level or vsomeip::security_level::SL_INVALID
     * if no record is found.
     */
    virtual security_level minimum_security_level(service_t _service, instance_t _instance, bool _provider) = 0;

    /**
     * \brief Returns whether the public key can be used for configuration signature
     * verification or not.
     */
    virtual bool can_verify_configuration_signature() = 0;
};

} // namespace vsomeip

#endif //VSOMEIP_DIGITAL_CERTIFICATE_HPP
