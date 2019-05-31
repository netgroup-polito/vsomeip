# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

find_program(OPENSSL_EXECUTABLE openssl)
if ("${OPENSSL_EXECUTABLE}" STREQUAL "OPENSSL_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "openssl not found. Impossible to proceed")
endif()
set(OPENSSL_LOG "${PROJECT_SOURCE_DIR}/crypto/generated/last_command.log")
set(CRYPTO_LOCK "${PROJECT_SOURCE_DIR}/crypto/generated")

# Convert the paths to relative with respect to the test folder
file(RELATIVE_PATH CRYPTO_CERTIFICATES_FOLDER_RELATIVE "${PROJECT_BINARY_DIR}/test/" "${CRYPTO_CERTIFICATES_FOLDER}")
file(RELATIVE_PATH CRYPTO_CHOSEN_KEY_RELATIVE "${PROJECT_BINARY_DIR}/test/" "${CRYPTO_CHOSEN_KEY}")

# Used as a workaround since cmake seems not to support the regex syntax '0{512}'
set(SIGNATURE_DEFAULT_128 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
set(SIGNATURE_DEFAULT ${SIGNATURE_DEFAULT_128}${SIGNATURE_DEFAULT_128}${SIGNATURE_DEFAULT_128}${SIGNATURE_DEFAULT_128})


# Computes the RSA2048(SHA256) signature of the specified configuration file,
# and updates the file itself with the computed value
# - CONFIGURATION_FILE: the configuration file to be signed
# - CONFIGURATION_SIGNER_KEY: the path of the key used to sign the configuration
# - OPENSSL_LOG: the path where the openssl log is saved in case of error
function(sign_configuration CONFIGURATION_FILE CONFIGURATION_SIGNATURE_KEY OPENSSL_LOG CRYPTO_LOCK)

    # Use a lock to prevent concurrent execution of file signature
    file(LOCK "${CRYPTO_LOCK}" DIRECTORY)

    execute_process(COMMAND "${OPENSSL_EXECUTABLE}" dgst -sha256 -hex -sign
            "${CONFIGURATION_SIGNATURE_KEY}" "${CONFIGURATION_FILE}"
            OUTPUT_VARIABLE SIGNATURE_RAW ERROR_FILE ${OPENSSL_LOG} RESULT_VARIABLE RESULT)
    if(NOT RESULT STREQUAL "0")
        message(FATAL_ERROR "Error: openssl failed. See log at ${OPENSSL_LOG}")
    endif()

    string(REGEX REPLACE "(^.* |\r|\n)" "" SIGNATURE ${SIGNATURE_RAW})
    file(READ "${CONFIGURATION_FILE}" CONFIGURATION_CONTENT)
    string(REGEX REPLACE "${SIGNATURE_DEFAULT}" "${SIGNATURE}" CONFIGURATION_CONTENT_SIGNED ${CONFIGURATION_CONTENT})
    file(WRITE "${CONFIGURATION_FILE}" ${CONFIGURATION_CONTENT_SIGNED})

    file(LOCK "${CRYPTO_LOCK}" DIRECTORY RELEASE)

endfunction()