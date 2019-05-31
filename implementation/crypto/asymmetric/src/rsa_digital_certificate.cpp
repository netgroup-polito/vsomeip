// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/rsa_digital_certificate.hpp"

#include <mutex>

#include <boost/algorithm/hex.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../include/rsa_public.hpp"
#include "../../common/include/crypto_types.hpp"
#include "../../../logging/include/logger.hpp"

namespace vsomeip {

/// \brief Converts a certificate fingerprint into an hexadecimal string.
static std::string hex_fingerprint(const certificate_fingerprint_t &_fingerprint) {
    std::string its_hex_fingerprint;
    boost::algorithm::hex(_fingerprint.begin(), _fingerprint.end(), std::back_inserter(its_hex_fingerprint));
    return its_hex_fingerprint;
}

/// \brief Extracts the human-readable certificate ID from the whole fingerprint.
static std::string certificate_id(const std::string &_hex_fingerprint) {
    return _hex_fingerprint.substr(0, 8) + ".." +
           _hex_fingerprint.substr(_hex_fingerprint.size() - 8, 8);
}

/**
 * \brief Returns an array of possible certificate paths.
 *
 * Every digital certificate is expected to be stored within the specified directory,
 * with the name composed of its fingerprint in hexadecimal format (either lowercase or
 * uppercase) and *.pem* as extension.
 *
 * @param _certificates_path the directory containing all the digital certificates.
 * @param _hex_fingerprint the fingerprint associated to the requested certificate.
 * @return the array containing the two possible paths (depending on the case of the fingeprint).
 */
static std::vector<std::string> certificate_paths(const std::string &_certificates_path, std::string _hex_fingerprint) {
    std::transform(_hex_fingerprint.begin(), _hex_fingerprint.end(), _hex_fingerprint.begin(), ::toupper);
    auto its_path_uc = _certificates_path + "/" + _hex_fingerprint + ".pem";
    std::transform(_hex_fingerprint.begin(), _hex_fingerprint.end(), _hex_fingerprint.begin(), ::tolower);
    auto its_path_lc = _certificates_path + "/" + _hex_fingerprint + ".pem";
    return { its_path_uc, its_path_lc };
}

/**
 * \brief Reads the requested digital certificate and returns the corresponding OpenSSL object.
 *
 * @param _certificate_id the human-readable identifier of the certificate.
 * @param _alternative_paths the list of alternative paths pointing to the certificate.
 * @return the OpenSSL object representing the certificate or nullptr in case of error.
 */
static X509_ptr rsa_read_x509_certificate(const std::string &_certificate_id,
                                          const std::vector<std::string> &_alternative_paths) {

    FILE *file = nullptr;
    auto paths_it = _alternative_paths.begin();
    while (paths_it != _alternative_paths.end() && nullptr == (file = std::fopen(paths_it->data(), "r"))) {
        paths_it++;
    }

    if (nullptr == file) {
        VSOMEIP_ERROR << "Failed to open certificate " << _certificate_id;
        return X509_ptr(nullptr, ::X509_free);
    }

    X509_ptr certificate(PEM_read_X509(file, nullptr, nullptr, nullptr), ::X509_free);
    std::fclose(file);

    if (!certificate) {
        VSOMEIP_ERROR << get_openssl_errors("failed to read certificate " + _certificate_id);
        return X509_ptr(nullptr, ::X509_free);
    }

    return certificate;
}

/**
 * \brief Verifies the integrity and authenticity of the given digital certificate.
 *
 * @param _certificate_id the human-readable identifier of the certificate.
 * @param _expected_fingerprint the expected fingerprint of the digital certificate.
 * @param _certificate the OpenSSL object representing the digital certificate.
 * @param _root_certificate the OpenSSL object representing the root digital certificate.
 * @return a value indicating whether the operation succeeded or not.
 */
static bool validate_certificate(const std::string &_certificate_id,
                                 const certificate_fingerprint_t &_expected_fingerprint,
                                 const X509_ptr &_certificate, const X509_ptr &_root_certificate) {

    certificate_fingerprint_t its_fingerprint{0};
    if (1 != X509_digest(_certificate.get(), EVP_sha256(), its_fingerprint.data(), nullptr)) {
        VSOMEIP_ERROR << "Failed to compute the fingerprint, certificate " << _certificate_id;
        return false;
    }

    if (its_fingerprint != _expected_fingerprint) {
        VSOMEIP_ERROR << "Actual fingerprint not corresponding to the expected one, certificate " << _certificate_id;
        return false;
    }

    X509_STORE_ptr store(X509_STORE_new(), ::X509_STORE_free);
    X509_STORE_CTX_ptr context(X509_STORE_CTX_new(), ::X509_STORE_CTX_free);

    if (nullptr != store && nullptr != context &&
            1 == X509_STORE_add_cert(store.get(), _root_certificate.get()) &&
            1 == X509_STORE_CTX_init(context.get(), store.get(), _certificate.get(), nullptr) &&
            1 == X509_verify_cert(context.get())) {
        return true;
    }

    VSOMEIP_ERROR << get_openssl_errors("failed to validate certificate " + _certificate_id);
    return false;
}

/**
 * \brief Extracts the public key contained wihin the digital certificate.
 *
 * @param _certificate_id the human-readable identifier of the certificate.
 * @param _certificate the OpenSSL object representing the digital certificate.
 * @param _expected_key_length the expected RSA key length (in bits).
 * @return the OpenSSL object representing the public key or nullptr in case of error.
 */
static EVP_PKEY_ptr extract_public_key(const std::string &_certificate_id, const X509_ptr &_certificate,
                                       rsa_key_length _expected_key_length) {

    EVP_PKEY_ptr evp_pkey(X509_get_pubkey(_certificate.get()), ::EVP_PKEY_free);
    RSA_ptr key(EVP_PKEY_get1_RSA(evp_pkey.get()), ::RSA_free);

    if (!key) {
        VSOMEIP_ERROR << "Invalid public key certificate '" << _certificate_id << "' - wrong type";
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    auto actual_key_length = static_cast<size_t>(RSA_size(key.get())) * 8;
    if (static_cast<size_t>(_expected_key_length) != actual_key_length) {
        VSOMEIP_ERROR << "Invalid public key certificate '" << _certificate_id << "' - expected length "
                      << static_cast<size_t>(_expected_key_length) << " found " << actual_key_length;
        return EVP_PKEY_ptr(nullptr, ::EVP_PKEY_free);
    }

    return evp_pkey;
}

/**
 * \brief Parses the information contained within a Subject Alternative Name element.
 *
 * @param _subject_alternative_name the string to be parsed.
 * @param _parsed_tuple the reference to the object where the triplet
 * (service ID, instance ID, is provider) is returned.
 * @return the minimum security level associated to specific triplet.
 */
static security_level parse_subject_alternative_name(std::string _subject_alternative_name,
                                                     std::tuple<service_t, instance_t, bool> &_parsed_tuple) {

    // Expected format: 'vsomeip:service:instance/role=level
    // role = { offer, request }
    // level = { nosec, authentication, confidentiality }
    const auto vsomeip = "vsomeip:";

    auto pos = _subject_alternative_name.find(vsomeip);
    if (std::string::npos == pos) {
        return security_level::SL_INVALID;
    }
    _subject_alternative_name.erase(0, std::strlen(vsomeip));

    auto pos_colon = _subject_alternative_name.find(':');
    auto pos_slash = _subject_alternative_name.find('/');
    auto pos_equal = _subject_alternative_name.find('=');

    std::string str_service = _subject_alternative_name.substr(0, pos_colon);
    std::string str_instance = _subject_alternative_name.substr(pos_colon + 1, pos_slash - pos_colon - 1);
    std::string str_role = _subject_alternative_name.substr(pos_slash + 1, pos_equal - pos_slash - 1);
    std::string str_level = _subject_alternative_name.substr(pos_equal + 1);

    std::stringstream its_converter_service;
    if (str_service.size() > 1 && str_service[0] == '0' && str_service[1] == 'x') {
        its_converter_service << std::hex << str_service;
    } else {
        its_converter_service << std::dec << str_service;
    }
    service_t its_service;
    its_converter_service >> its_service;

    std::stringstream its_converter_instance;
    if (str_instance.size() > 1 && str_instance[0] == '0' && str_instance[1] == 'x') {
        its_converter_instance << std::hex << str_instance;
    } else {
        its_converter_instance << std::dec << str_instance;
    }
    instance_t its_instance;
    its_converter_instance >> its_instance;

    bool its_role;
    if ("offer" == str_role) {
        its_role = true;
    } else if ("request" == str_role) {
        its_role = false;
    } else {
        return security_level::SL_INVALID;
    }

    std::stringstream its_converter_level;
    its_converter_level << str_level;
    security_level its_security_level;
    its_converter_level >> its_security_level;

    std::get<0>(_parsed_tuple) = its_service;
    std::get<1>(_parsed_tuple) = its_instance;
    std::get<2>(_parsed_tuple) = its_role;
    return its_security_level;
}

/**
 * \brief Processes the information contained within the Subject Alternative Names
 * section of the digital certificate.
 *
 * @param _certificate_id the human-readable identifier of the certificate.
 * @param _certificate the OpenSSL object representing the digital certificate.
 * @param _can_verify_configuration_signature the reference to the variable where it is saved.
 * whether the certificate can be used to verify configuration file signatures or not.
 * @return the map associating to each triplet (service ID, instance ID, is provider) the
 * corresponding security level.
 */
static std::map<std::tuple<service_t, instance_t, bool>, security_level>
get_subject_alternative_names(const std::string &_certificate_id, const X509_ptr &_certificate,
                              bool &_can_verify_configuration_signature) {

    const auto can_verify_configuration_signature_san = "vsomeip:configuration-signature";
    std::map<std::tuple<service_t, instance_t, bool>, security_level> minimum_security_levels;

    auto subject_alternative_names = reinterpret_cast<GENERAL_NAMES *>(
            X509_get_ext_d2i(_certificate.get(), NID_subject_alt_name, nullptr, nullptr));
    if (nullptr == subject_alternative_names) {
        return {};
    }

    int subject_alternative_names_count = sk_GENERAL_NAME_num(subject_alternative_names);
    for (int i = 0; i < subject_alternative_names_count; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(subject_alternative_names, i);

        if (current_name->type == GEN_URI) {
            std::string subject_alternative_name(
                    reinterpret_cast<const char *>(ASN1_STRING_get0_data(current_name->d.uniformResourceIdentifier)),
                    static_cast<size_t>(ASN1_STRING_length(current_name->d.uniformResourceIdentifier)));

            if (can_verify_configuration_signature_san == subject_alternative_name) {
                _can_verify_configuration_signature = true;
                continue;
            }

            std::tuple<service_t, instance_t, bool> its_tuple;
            security_level its_security_level = parse_subject_alternative_name(subject_alternative_name, its_tuple);
            if (security_level::SL_INVALID == its_security_level) {
                VSOMEIP_WARNING << "Unrecognized Subject Alternative Name, certificate " << _certificate_id;
                continue;
            }

            minimum_security_levels[its_tuple] = its_security_level;

        } else {
            VSOMEIP_WARNING << "Certificate file with unrecognized Subject Alternative Name " << _certificate_id;
        }
    }

    return minimum_security_levels;
};

/**
 * \brief Reads and validates the root digital certificate.
 *
 * @param _certificates_path the directory where digital certificates are stored.
 * @param _fingerprint the fingerprint associated to the root certificate.
 * @return the OpenSSL object representing the digital certificate.
 */
static X509_ptr rsa_load_root_x509_certificate(const std::string &_certificates_path,
                                               const certificate_fingerprint_t &_fingerprint) {

    auto its_hex_fingerprint(hex_fingerprint(_fingerprint));
    auto its_certificate_id(certificate_id(its_hex_fingerprint));
    auto its_certificate_paths(certificate_paths(_certificates_path, its_hex_fingerprint));

    X509_ptr root_certificate(rsa_read_x509_certificate(its_certificate_id, its_certificate_paths));

    if (!root_certificate ||
            !validate_certificate(its_certificate_id, _fingerprint, root_certificate, root_certificate)) {
        VSOMEIP_ERROR << "Failed to load root certificate " << its_certificate_id;
        return X509_ptr(nullptr, ::X509_free);
    }

    VSOMEIP_INFO << "Loaded root certificate " << its_certificate_id;
    return root_certificate;
}


std::shared_ptr<digital_certificate>
rsa_digital_certificate::get_certificate(const std::string &_certificates_path,
                                         const certificate_fingerprint_t &_fingerprint,
                                         const certificate_fingerprint_t &_root_fingerprint,
                                         rsa_key_length _expected_key_length,
                                         digest_algorithm _digest_algorithm) {

    static std::mutex its_mutex;
    static std::map<certificate_fingerprint_t, std::shared_ptr<digital_certificate>> cached_certificates;

    std::lock_guard<std::mutex> its_lock(its_mutex);

    static X509_ptr root_certificate = rsa_load_root_x509_certificate(_certificates_path, _root_fingerprint);

    auto its_hex_fingerprint(hex_fingerprint(_fingerprint));
    auto its_certificate_id(certificate_id(its_hex_fingerprint));
    auto its_certificate_paths(certificate_paths(_certificates_path, its_hex_fingerprint));

    if (!root_certificate) {
        VSOMEIP_ERROR << "Impossible to load certificate " << its_certificate_id
                      << " - invalid root certificate";
        return std::shared_ptr<digital_certificate>(new rsa_digital_certificate());
    }

    const auto &its_found = cached_certificates.find(_fingerprint);
    if (its_found != cached_certificates.end()) {
        return its_found->second;
    }

    auto time_begin = std::chrono::steady_clock::now();
    auto its_certificate = std::shared_ptr<digital_certificate>(
            new rsa_digital_certificate(its_certificate_id, its_certificate_paths, _fingerprint, root_certificate,
                                        _expected_key_length, _digest_algorithm));
    auto time_end = std::chrono::steady_clock::now();
    if (its_certificate->is_valid()) {
        auto elapsed_time_us = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_begin).count();
        VSOMEIP_INFO << "Loaded certificate " << its_certificate_id << " in "
                     << std::fixed << std::setprecision(1) << static_cast<double>(elapsed_time_us) / 1000 << " ms";
        cached_certificates[_fingerprint] = its_certificate;
    }

    return its_certificate;
}


rsa_digital_certificate::rsa_digital_certificate(std::string _certificate_id,
                                                 const std::vector<std::string> &_certificate_alternative_paths,
                                                 const certificate_fingerprint_t &_expected_fingerprint,
                                                 const X509_ptr &_root_certificate,
                                                 rsa_key_length _expected_key_length,
                                                 digest_algorithm _digest_algorithm)
        : can_verify_configuration_signature_(false) {

    auto certificate = rsa_read_x509_certificate(_certificate_id, _certificate_alternative_paths);
    if (nullptr == certificate) {
        return;
    }

    if (!validate_certificate(_certificate_id, _expected_fingerprint, certificate, _root_certificate)) {
        return;
    }

    auto public_key = extract_public_key(_certificate_id, certificate, _expected_key_length);
    if (nullptr == public_key) {
        return;
    }

    public_key_ = std::make_shared<rsa_public>(std::move(public_key), _expected_key_length, _digest_algorithm);
    certificate_fingerprint_ = _expected_fingerprint;
    minimum_security_levels_ = get_subject_alternative_names(_certificate_id, certificate,
                                                             can_verify_configuration_signature_);
}

bool rsa_digital_certificate::is_valid() {
    return static_cast<bool>(public_key_);
}

std::shared_ptr<asymmetric_crypto_public> rsa_digital_certificate::get_public_key() {
    return public_key_;
}

const certificate_fingerprint_t &rsa_digital_certificate::get_fingerprint() {
    return certificate_fingerprint_;
}

security_level
rsa_digital_certificate::minimum_security_level(service_t _service, instance_t _instance, bool _provider) {

    auto its_found = minimum_security_levels_.find(std::make_tuple(_service, _instance, _provider));
    if (its_found != minimum_security_levels_.end()) {
        return its_found->second;
    }

    return _provider
           ? security_level::SL_INVALID
           /* In case the application is allowed to offer a service, it is also allowed to request it */
           : minimum_security_level(_service, _instance, true);
}

bool rsa_digital_certificate::can_verify_configuration_signature() {
    return can_verify_configuration_signature_;
}

} // namespace vsomeip
