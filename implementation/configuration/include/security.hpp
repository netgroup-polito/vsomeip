// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CFG_SECURITY_HPP
#define VSOMEIP_CFG_SECURITY_HPP

#include <map>
#include <vsomeip/primitive_types.hpp>

#include "internal.hpp"
#include "../../crypto/common/include/algorithms.hpp"

namespace vsomeip {
namespace cfg {

struct service_security {

    service_security() :
            certificates_path_(VSOMEIP_DEFAULT_CERTIFICATES_PATH), default_private_key_path_(),
            root_certificate_fingerprint_{0}, default_certificate_fingerprint_{0},
            session_establishment_max_repetitions_(VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_MAX_REPETITIONS),
            session_establishment_repetitions_delay_(VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_REPETITIONS_DELAY),
            session_establishment_repetitions_delay_ratio_(VSOMEIP_DEFAULT_SESSION_ESTABLISHMENT_REPETITIONS_DELAY_RATIO),
            check_application_fingerprints_(false) {

        default_algorithms_[security_level::SL_NOSEC] = { security_level::SL_NOSEC, VSOMEIP_DEFAULT_ALGORITHM_NOSEC };
        default_algorithms_[security_level::SL_AUTHENTICATION] = { security_level::SL_AUTHENTICATION, VSOMEIP_DEFAULT_ALGORITHM_AUTHENTICATION };
        default_algorithms_[security_level::SL_CONFIDENTIALITY] = { security_level::SL_CONFIDENTIALITY, VSOMEIP_DEFAULT_ALGORITHM_CONFIDENTIALITY };
    }

    crypto_algorithm_packed get_crypto_algorithm(service_t _service, instance_t _instance) const {
        auto its_found = services_algorithms_.find({_service, _instance});
        if (its_found != services_algorithms_.end()) {
            return crypto_algorithm::CA_INVALID == its_found->second.crypto_algorithm_
                   ? get_default_crypto_algorithm(its_found->second.security_level_)
                   : its_found->second;
        }
        return { };
    }

    crypto_algorithm_packed get_default_crypto_algorithm(security_level _security_level) const {
        auto its_found = default_algorithms_.find(_security_level);
        if (its_found != default_algorithms_.end()) {
            return its_found->second;
        }
        return { };
    }

    std::string certificates_path_;
    std::string default_private_key_path_;
    certificate_fingerprint_t root_certificate_fingerprint_;
    certificate_fingerprint_t default_certificate_fingerprint_;

    uint8_t session_establishment_max_repetitions_;
    uint32_t session_establishment_repetitions_delay_;
    float session_establishment_repetitions_delay_ratio_;

    std::map<std::pair<service_t, instance_t>, crypto_algorithm_packed> services_algorithms_;
    std::map<security_level, crypto_algorithm_packed> default_algorithms_;
    bool check_application_fingerprints_;
};

struct configuration_security {

    configuration_security() :
        signature_algorithm_(asymmetric_crypto_algorithm::CA_INVALID),
        certificate_fingerprint_{0} {
    }

    asymmetric_crypto_algorithm signature_algorithm_;
    certificate_fingerprint_t certificate_fingerprint_;
    signature_t signature_;
};

} // namespace cfg
} // namespace vsomeip

#endif //VSOMEIP_CFG_SECURITY_HPP
