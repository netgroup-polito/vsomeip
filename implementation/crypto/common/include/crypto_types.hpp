// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CRYPTO_TYPES_HPP
#define VSOMEIP_CRYPTO_TYPES_HPP

#include <memory>
#include <vector>

#include <openssl/ossl_typ.h>

#include <vsomeip/primitive_types.hpp>
#include "crypto_utility.hpp"

extern "C" void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);
extern "C" void EVP_MD_CTX_free(EVP_MD_CTX *);
extern "C" void EVP_PKEY_CTX_free(EVP_PKEY_CTX *);
extern "C" void EVP_PKEY_free(EVP_PKEY *);
extern "C" void RSA_free(RSA *);
extern "C" void X509_free(X509 *);
extern "C" void X509_STORE_free(X509_STORE *);
extern "C" void X509_STORE_CTX_free(X509_STORE_CTX *);

namespace vsomeip {

/// \brief The data type used to store sensible material, which needs to be zeroed when no more in use.
template<typename T>
using secure_vector = std::vector<T, zallocator<T>>;
/// \brief The data type used to store digital signatures.
using signature_t = std::vector<byte_t>;
/// \brief The data type used to store digital certificate fingerprints.
using certificate_fingerprint_t = std::array<byte_t, (256/8) /* SHA256 */>;
/// \brief The data type used to store application fingerprints.
using application_fingerprint_t = std::array<byte_t, (256/8) /* SHA256 */>;
/// \brief The data type used to represent the identifier associated to each member of a secure session.
using crypto_instance_t = std::uint16_t;

/* Utility wrappers to guarantee the correct management of the lifecycle of OpenSSL objects */
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509_STORE_ptr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;
using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;

} // namespace vsomeip

#endif //VSOMEIP_CRYPTO_TYPES_HPP
