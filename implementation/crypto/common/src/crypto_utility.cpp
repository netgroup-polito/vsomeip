// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/crypto_utility.hpp"

#include <iomanip>
#include <sstream>

#include <openssl/err.h>
#include <openssl/x509.h>

namespace vsomeip {

std::string get_openssl_errors(const std::string &message) {

    std::stringstream oss;
    oss << "OpenSSL: " << message;

    unsigned long err_code;
    while (0 != (err_code = ERR_get_error())) {
        oss << " - " << std::hex << std::setfill('0') << std::setw(8) << err_code;
    }

    return oss.str();
}

} // namespace vsomeip