# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Computes the fingerprint of the specified certificate
function(compute_fingerprint CERTIFICATE OUTPUT)
    execute_process(COMMAND "${OPENSSL_EXECUTABLE}" x509 -noout -fingerprint -sha256 -inform pem
            -in "${CERTIFICATE}"
            OUTPUT_VARIABLE FINGERPRINT_RAW ERROR_FILE "${OPENSSL_LOG}" RESULT_VARIABLE RESULT)
    if(NOT RESULT STREQUAL "0")
        message(FATAL_ERROR "Error: openssl failed. See log at ${OPENSSL_LOG}")
    endif()

    string(REGEX REPLACE "(SHA256 Fingerprint=|:|\r|\n)" "" FINGERPRINT ${FINGERPRINT_RAW})
    set(${OUTPUT} ${FINGERPRINT} PARENT_SCOPE)
endfunction()

# Generates the pair private key, certificate for a given security level
function(generate_crypto_material LEVEL FORCE)
    string(TOUPPER ${LEVEL} LEVEL_UC)

    if (FORCE OR NOT EXISTS "${CRYPTO_${LEVEL_UC}_KEY}" OR NOT EXISTS "${CRYPTO_CERTIFICATES_FOLDER}/${CRYPTO_${LEVEL_UC}_CERTIFICATE}.pem")
        message(STATUS "Generating private key and certificate for security level ${LEVEL_UC}...")

        execute_process(COMMAND "${OPENSSL_EXECUTABLE}" req -new -sha256 -nodes
                -out "${CRYPTO_CSR_FOLDER}/${LEVEL}.csr" -newkey rsa:2048 -keyout "${CRYPTO_PRIVATE_KEYS_FOLDER}/${LEVEL}.key"
                -config "${OPENSSL_CONFIG_FILE_${LEVEL_UC}}"
                ERROR_FILE "${OPENSSL_LOG}" RESULT_VARIABLE RESULT)
        if(NOT RESULT STREQUAL "0")
            message(FATAL_ERROR "Error: openssl failed. See log at ${OPENSSL_LOG}")
        endif()

        execute_process(COMMAND "${OPENSSL_EXECUTABLE}" x509 -req -days 365 -in "${CRYPTO_CSR_FOLDER}/${LEVEL}.csr"
                -CA "${CRYPTO_CERTIFICATES_FOLDER}/${CRYPTO_ROOT_CA_CERTIFICATE}.pem" -CAkey "${CRYPTO_ROOT_CA_KEY}" -CAcreateserial
                -out "${CRYPTO_CERTIFICATES_FOLDER}/${LEVEL}.pem" -extfile "${OPENSSL_CONFIG_FILE_${LEVEL_UC}}"
                -extensions req_ext
                ERROR_FILE "${OPENSSL_LOG}" RESULT_VARIABLE RESULT)
        if(NOT RESULT STREQUAL "0")
            message(FATAL_ERROR "Error: openssl failed. See log at ${OPENSSL_LOG}")
        endif()

        compute_fingerprint("${CRYPTO_CERTIFICATES_FOLDER}/${LEVEL}.pem" FINGERPRINT)
        set(CRYPTO_${LEVEL_UC}_KEY "${CRYPTO_PRIVATE_KEYS_FOLDER}/${LEVEL}.key" PARENT_SCOPE)
        set(CRYPTO_${LEVEL_UC}_CERTIFICATE "${FINGERPRINT}" PARENT_SCOPE)
        file(RENAME "${CRYPTO_CERTIFICATES_FOLDER}/${LEVEL}.pem" "${CRYPTO_CERTIFICATES_FOLDER}/${FINGERPRINT}.pem")
    endif()
endfunction()


find_program(OPENSSL_EXECUTABLE openssl)
if ("${OPENSSL_EXECUTABLE}" STREQUAL "OPENSSL_EXECUTABLE-NOTFOUND")
    message(WARNING "openssl not found. Impossible to generate the crypto material")
else()

    set(CRYPTO_CONFIG_PATH "${CRYPTO_BASE_PATH}/config")
    set(OPENSSL_CONFIG_FILE_ROOT_CA "${CRYPTO_CONFIG_PATH}/openssl-root-ca.cnf")
    set(OPENSSL_CONFIG_FILE_NOSEC "${CRYPTO_CONFIG_PATH}/openssl-nosec.cnf")
    set(OPENSSL_CONFIG_FILE_AUTHENTICATION "${CRYPTO_CONFIG_PATH}/openssl-authentication.cnf")
    set(OPENSSL_CONFIG_FILE_CONFIDENTIALITY "${CRYPTO_CONFIG_PATH}/openssl-confidentiality.cnf")
    set(OPENSSL_CONFIG_FILE_CONFIGURATION_SIGNATURE "${CRYPTO_CONFIG_PATH}/openssl-configuration-signature.cnf")

    set(CRYPTO_CACHE_FILE "${CRYPTO_GENERATED_PATH}/cache.txt")
    set(CRYPTO_PRIVATE_KEYS_FOLDER "${CRYPTO_GENERATED_PATH}/keys")
    set(CRYPTO_CERTIFICATES_FOLDER "${CRYPTO_GENERATED_PATH}/certificates")
    set(CRYPTO_CSR_FOLDER "${CRYPTO_GENERATED_PATH}/csr")

    set(OPENSSL_LOG "${CRYPTO_GENERATED_PATH}/last_command.log")

    # Create the necessary directories
    file(MAKE_DIRECTORY "${CRYPTO_GENERATED_PATH}")
    file(MAKE_DIRECTORY "${CRYPTO_PRIVATE_KEYS_FOLDER}")
    file(MAKE_DIRECTORY "${CRYPTO_CERTIFICATES_FOLDER}")
    file(MAKE_DIRECTORY "${CRYPTO_CSR_FOLDER}")

    # Use a lock to prevent concurrent execution of crypto material generation
    file(LOCK "${CRYPTO_GENERATED_PATH}" DIRECTORY)

    # Read cryptographic material location from cache
    if(EXISTS "${CRYPTO_CACHE_FILE}")
        file(READ "${CRYPTO_CACHE_FILE}" VARIABLES)
        string(REGEX REPLACE "\n" ";" VARIABLES "${VARIABLES}")
        foreach(VARIABLE ${VARIABLES})
            string(REGEX REPLACE "\t" ";" VARIABLE "${VARIABLE}")
            list(GET VARIABLE 0 NAME)
            list(GET VARIABLE 1 VALUE)
            set("${NAME}" "${VALUE}")
        endforeach()
    endif()

    # Generate the root CA private key and certificate
    set(CRYPTO_ROOT_CA_KEY "${CRYPTO_PRIVATE_KEYS_FOLDER}/root.key")
    if(NOT EXISTS "${CRYPTO_CERTIFICATES_FOLDER}/${CRYPTO_ROOT_CA_CERTIFICATE}.pem" OR NOT EXISTS "${CRYPTO_ROOT_CA_KEY}")
        set(FORCE TRUE)
        message(STATUS "Generating private key and certificate for ROOT CA...")
        execute_process(COMMAND "${OPENSSL_EXECUTABLE}" req -x509 -newkey rsa:2048 -sha256 -nodes
                -keyout "${CRYPTO_PRIVATE_KEYS_FOLDER}/root.key" -out "${CRYPTO_CERTIFICATES_FOLDER}/root.pem" -days 365
                -config "${OPENSSL_CONFIG_FILE_ROOT_CA}" -extensions req_ext
                ERROR_FILE "${OPENSSL_LOG}" RESULT_VARIABLE RESULT)
        if(NOT RESULT STREQUAL "0")
            message(FATAL_ERROR "Error: openssl failed. See log at ${OPENSSL_LOG}")
        endif()

        compute_fingerprint("${CRYPTO_CERTIFICATES_FOLDER}/root.pem" FINGERPRINT)
        set(CRYPTO_ROOT_CA_CERTIFICATE ${FINGERPRINT} CACHE STRING
                "The fingerprint corresponding to the ROOT CA certificate" FORCE)
        file(RENAME "${CRYPTO_CERTIFICATES_FOLDER}/root.pem" "${CRYPTO_CERTIFICATES_FOLDER}/${CRYPTO_ROOT_CA_CERTIFICATE}.pem")
    else()
        set(FORCE FALSE)
    endif()

    # Generate the private key and certificate for the selected security level
    generate_crypto_material(${CONFIGURATION_SECURITY_LEVEL} ${FORCE})
    set(CRYPTO_CHOSEN_KEY "${CRYPTO_${CONFIGURATION_SECURITY_LEVEL_UC}_KEY}" CACHE FILEPATH
            "The path pointing to the key related to the coresponding security level" FORCE)
    set(CRYPTO_CHOSEN_CERTIFICATE "${CRYPTO_${CONFIGURATION_SECURITY_LEVEL_UC}_CERTIFICATE}" CACHE STRING
            "The certificate fingerprint coresponding to the chosen security level" FORCE)

    # Generate the private key and certificate used for configuration signature
    generate_crypto_material("configuration_signature" ${FORCE})
    set(CRYPTO_CONFIGURATION_SIGNATURE_KEY "${CRYPTO_CONFIGURATION_SIGNATURE_KEY}" CACHE FILEPATH
            "The path pointing to the CONFIGURATION_SIGNATURE key" FORCE)
    set(CRYPTO_CONFIGURATION_SIGNATURE_CERTIFICATE "${CRYPTO_CONFIGURATION_SIGNATURE_CERTIFICATE}" CACHE STRING
            "The fingerprint corresponding to the CONFIGURATION_SIGNATURE certificate" FORCE)

    # Store cryptographic material location in cache
    file(WRITE ${CRYPTO_CACHE_FILE} "CRYPTO_ROOT_CA_CERTIFICATE\t${CRYPTO_ROOT_CA_CERTIFICATE}\n")
    foreach(LEVEL NOSEC AUTHENTICATION CONFIDENTIALITY CONFIGURATION_SIGNATURE)
        file(APPEND ${CRYPTO_CACHE_FILE} "CRYPTO_${LEVEL}_KEY\t${CRYPTO_${LEVEL}_KEY}\n")
        file(APPEND ${CRYPTO_CACHE_FILE} "CRYPTO_${LEVEL}_CERTIFICATE\t${CRYPTO_${LEVEL}_CERTIFICATE}\n")
    endforeach()

    # End of locked section
    file(LOCK "${CRYPTO_GENERATED_PATH}" DIRECTORY RELEASE)

endif()