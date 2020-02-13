// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_ALGORITHMS_HPP
#define VSOMEIP_ALGORITHMS_HPP

#include <cstdint>
#include <ostream>

#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip {

/// \brief The enumeration of the available security level.
enum class security_level : uint8_t {
    SL_INVALID = 0x00,         ///< \brief Invalid.
    SL_NOSEC = 0x01,           ///< \brief Nosec: no security guarantees.
    SL_AUTHENTICATION = 0x02,  ///< \brief Authentication: data authentication, integrity and replay protection.
    SL_CONFIDENTIALITY = 0x03, ///< \brief Confidentiality: data authentication, integrity, confidentiality and replay protection.
};

/// \brief The enumeration of the provided symmetric cryptography algorithms.
enum class crypto_algorithm : uint8_t {
    CA_INVALID = 0x00,                             ///< \brief Invalid.
    CA_NULL = 0x11,                                ///< \brief Null.
    CA_CHACHA20_POLY1305_256 = 0x21,               ///< \brief CHACHA20-POLY1305 (256 bits key).
    CA_AES_GCM_128 = 0x22,                         ///< \brief AES-GCM (128 bits key).
    CA_AES_GCM_256 = 0x23,                         ///< \brief AES-GCM (256 bits key).
    CA_AES_CCM_128 = 0x24,                         ///< \brief AES-CCM (128 bits key).
    CA_AES_CCM_256 = 0x25,                         ///< \brief AES-CCM (256 bits key).
};

/// \brief The enumeration of the key lengths available for AES-based algorithms.
enum class aes_key_length : size_t {
    AES_128 = 128,             ///< \brief 128 bits.
    AES_256 = 256,             ///< \brief 256 bits.
};

/// \brief The enumeration of the provided asymmetric cryptography algorithms.
enum class asymmetric_crypto_algorithm : uint8_t {
    CA_INVALID = 0x00,         ///< \brief Invalid.
    CA_RSA2048_SHA256 = 0x01,  ///< \brief RSA2048 using SHA256 as digest algorithm.
};

/// \brief The enumeration of the key lengths available for RSA-based algorithms.
enum class rsa_key_length : size_t {
    RSA_2048 = 2048,           ///< \brief 2048 bits.
};

/// \brief The enumeration of the provided message digest algorithms.
enum class digest_algorithm : uint8_t {
    MD_SHA256 = 0x01,          ///< \brief SHA256.
};

/// \brief This class bundles together a security level with the associated symmetric algorithm.
struct crypto_algorithm_packed {
    security_level security_level_;
    crypto_algorithm crypto_algorithm_;

    /// \brief Constructs an instance characterized by invalid values.
    crypto_algorithm_packed() :
            crypto_algorithm_packed(security_level::SL_INVALID, crypto_algorithm::CA_INVALID) {
    }

    /// \brief Constructs an instance using the parameters as values.
    crypto_algorithm_packed(security_level _security_level, crypto_algorithm _crypto_algorithm)
            : security_level_(_security_level), crypto_algorithm_(_crypto_algorithm) {
    }

    /// \brief Returns whether the stored combination is valid or not.
    bool is_valid_combination() {
        return (security_level::SL_NOSEC == security_level_ &&
                crypto_algorithm::CA_NULL == crypto_algorithm_) ||
               (security_level::SL_NOSEC != security_level_ && (
                       crypto_algorithm::CA_CHACHA20_POLY1305_256 == crypto_algorithm_ ||
                       crypto_algorithm::CA_AES_GCM_128 == crypto_algorithm_ ||
                       crypto_algorithm::CA_AES_GCM_256 == crypto_algorithm_ ||
                       crypto_algorithm::CA_AES_CCM_128 == crypto_algorithm_ ||
                       crypto_algorithm::CA_AES_CCM_256 == crypto_algorithm_));
    }
};

VSOMEIP_EXPORT std::ostream &operator<<(std::ostream &_os, security_level _security_level);
VSOMEIP_EXPORT std::istream &operator>>(std::istream &_is, security_level &_security_level);

VSOMEIP_EXPORT std::ostream &operator<<(std::ostream &_os, crypto_algorithm _crypto_algorithm);
VSOMEIP_EXPORT std::istream &operator>>(std::istream &_is, crypto_algorithm &_crypto_algorithm);

VSOMEIP_EXPORT std::ostream &operator<<(std::ostream &_os, asymmetric_crypto_algorithm _asymmetric_crypto_algorithm);
VSOMEIP_EXPORT std::istream &operator>>(std::istream &_is, asymmetric_crypto_algorithm &_asymmetric_crypto_algorithm);

} // namespace vsomeip

#endif //VSOMEIP_ALGORITHMS_HPP
