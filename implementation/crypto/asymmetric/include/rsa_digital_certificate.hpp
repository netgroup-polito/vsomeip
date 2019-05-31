// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_RSA_DIGITAL_CERTIFICATE_HPP
#define VSOMEIP_RSA_DIGITAL_CERTIFICATE_HPP

#include <map>
#include "digital_certificate.hpp"

namespace vsomeip {

/**
 * \brief Class implementing the vsomeip::digital_certificate
 * interface for RSA digital certificates.
 */
class rsa_digital_certificate : public digital_certificate {

public:
    /**
     * \brief Returns the instance of the requested digital certificate.
     *
     * This function provides access to the certificate store, hiding the process
     * of reading and validating the certificates. Additionally, it guarantees that
     * the same instance is reused if requested multiple times, to prevent the
     * need for repeated expensive operations. The access to the store is
     * automatically synchronized and therefore concurrent execution is safe.
     *
     * @param _certificates_path the directory where certificates are stored.
     * @param _fingerprint the fingerprint identifying the requested certificate.
     * @param _root_fingerprint the fingerprint identifying the root certificate.
     * @param _expected_key_length the expected RSA key length (in bits).
     * @param _digest_algorithm the digest algorithm to be used in conjunction with RSA.
     * @return the retrieved certificate or an invalid instance in case of error.
     */
    static std::shared_ptr<digital_certificate>
    get_certificate(const std::string &_certificates_path,
                    const certificate_fingerprint_t &_fingerprint,
                    const certificate_fingerprint_t &_root_fingerprint,
                    rsa_key_length _expected_key_length,
                    digest_algorithm _digest_algorithm);

public:
    ~rsa_digital_certificate() override = default;

    bool is_valid() override;

    std::shared_ptr<asymmetric_crypto_public> get_public_key() override;

    const certificate_fingerprint_t & get_fingerprint() override;

    security_level minimum_security_level(service_t _service, instance_t _instance, bool _provider) override;

    bool can_verify_configuration_signature() override;

private:
    /**
     * \brief Creates a new *invalid* instance of this class.
     */
    rsa_digital_certificate() = default;

    /**
     * \brief Creates a new instance of this class.
     *
     * @param _certificate_id the human-readable identifier of the digital certificate.
     * @param _certificate_alternative_paths the list of alternative paths pointing to the certificate.
     * @param _expected_fingerprint the expected fingerprint of the digital certificate.
     * @param _root_certificate the OpenSSL object representing the root certificate.
     * @param _expected_key_length the expected RSA key length (in bits).
     * @param _digest_algorithm the digest algorithm to be used in conjunction with RSA.
     */
    rsa_digital_certificate(std::string _certificate_id, const std::vector<std::string> &_certificate_alternative_paths,
                            const certificate_fingerprint_t &_expected_fingerprint, const X509_ptr &_root_certificate,
                            rsa_key_length _expected_key_length, digest_algorithm _digest_algorithm);

private:
    std::shared_ptr<asymmetric_crypto_public> public_key_;
    certificate_fingerprint_t certificate_fingerprint_;
    std::map<std::tuple<service_t, instance_t, bool>, security_level> minimum_security_levels_;
    bool can_verify_configuration_signature_;
};

} // namespace vsomeip

#endif //VSOMEIP_RSA_DIGITAL_CERTIFICATE_HPP
