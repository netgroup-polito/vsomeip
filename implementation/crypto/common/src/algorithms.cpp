// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/algorithms.hpp"

#include <algorithm>

namespace vsomeip {

std::ostream &operator<<(std::ostream &_os, security_level _security_level) {
    switch (_security_level) {
        case security_level::SL_NOSEC:
            return _os << "nosec";
        case security_level::SL_AUTHENTICATION:
            return _os << "authentication";
        case security_level::SL_CONFIDENTIALITY:
            return _os << "confidentiality";
        case security_level::SL_INVALID:
            return _os << "invalid";
    }
    return _os << "invalid";
}

std::istream &operator>>(std::istream &_is, security_level &_security_level) {
    std::string its_security_level;
    _is >> its_security_level;
    std::transform(its_security_level.begin(), its_security_level.end(), its_security_level.begin(), ::tolower);

    if ("nosec" == its_security_level) {
        _security_level = security_level::SL_NOSEC;
    } else if ("authentication" == its_security_level) {
        _security_level = security_level::SL_AUTHENTICATION;
    } else if ("confidentiality" == its_security_level) {
        _security_level = security_level::SL_CONFIDENTIALITY;
    } else {
        _security_level = security_level::SL_INVALID;
    }

    return _is;
}

std::ostream &operator<<(std::ostream &_os, crypto_algorithm _crypto_algorithm) {
    switch (_crypto_algorithm) {
        case crypto_algorithm::CA_NULL:
            return _os << "null";
        case crypto_algorithm::CA_CHACHA20_POLY1305_256:
            return _os << "chacha20-poly1305-256";
        case crypto_algorithm::CA_AES_GCM_128:
            return _os << "aes-gcm-128";
        case crypto_algorithm::CA_AES_GCM_256:
            return _os << "aes-gcm-256";
        case crypto_algorithm::CA_AES_CCM_128:
            return _os << "aes-ccm-128";
        case crypto_algorithm::CA_AES_CCM_256:
            return _os << "aes-ccm-256";
        case crypto_algorithm::CA_INVALID:
            return _os << "invalid";
    }
    return _os << "invalid";
}

std::istream &operator>>(std::istream &_is, crypto_algorithm &_crypto_algorithm) {
    std::string its_crypto_algorithm;
    _is >> its_crypto_algorithm;
    std::transform(its_crypto_algorithm.begin(), its_crypto_algorithm.end(), its_crypto_algorithm.begin(), ::tolower);

    if ("null" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm ::CA_NULL;
    } else if ("chacha20-poly1305-256" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm::CA_CHACHA20_POLY1305_256;
    } else if ("aes-gcm-128" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm::CA_AES_GCM_128;
    } else if ("aes-gcm-256" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm::CA_AES_GCM_256;
    } else if ("aes-ccm-128" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm::CA_AES_CCM_128;
    } else if ("aes-ccm-256" == its_crypto_algorithm) {
        _crypto_algorithm = crypto_algorithm::CA_AES_CCM_256;
    } else {
        _crypto_algorithm = crypto_algorithm::CA_INVALID;
    }

    return _is;
}

std::ostream &operator<<(std::ostream &_os, asymmetric_crypto_algorithm _asymmetric_crypto_algorithm) {
    switch (_asymmetric_crypto_algorithm) {
        case asymmetric_crypto_algorithm::CA_RSA2048_SHA256:
            return _os << "rsa2048-sha256";
        case asymmetric_crypto_algorithm::CA_INVALID:
            return _os << "invalid";
    }
    return _os << "invalid";
}

std::istream &operator>>(std::istream &_is, asymmetric_crypto_algorithm &_asymmetric_crypto_algorithm) {
    std::string its_crypto_algorithm;
    _is >> its_crypto_algorithm;
    std::transform(its_crypto_algorithm.begin(), its_crypto_algorithm.end(), its_crypto_algorithm.begin(), ::tolower);

    if ("rsa2048-sha256" == its_crypto_algorithm) {
        _asymmetric_crypto_algorithm = asymmetric_crypto_algorithm::CA_RSA2048_SHA256;
    } else {
        _asymmetric_crypto_algorithm = asymmetric_crypto_algorithm::CA_INVALID;
    }

    return _is;
}

} // namespace vsomeip