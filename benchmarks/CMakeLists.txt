# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 2.8.1)

include(${CRYPTO_BASE_PATH}/sign_configuration_file.cmake)

set(BENCH_OUTPUT "${PROJECT_BINARY_DIR}/benchmarks")
set(BENCH_CONFIG_OUTPUT ${BENCH_OUTPUT}/conf)
file(MAKE_DIRECTORY "${BENCH_CONFIG_OUTPUT}")

# Function to copy files into the build directory (or anywhere else)
# On unixoid systems this function will create symlinks instead
# SOURCE_PATH: Path to the file which should be copied
# DESTINATION_PATH: destination file
# TARGET_TO_DEPEND: The copying of the file will be added as
#                   a dependency to this target
function(copy_to_builddir SOURCE_PATH DESTINATION_PATH TARGET_TO_DEPEND)

    ADD_CUSTOM_COMMAND(
            OUTPUT "${DESTINATION_PATH}"
            COMMAND ${CMAKE_COMMAND} -E copy "${SOURCE_PATH}" "${DESTINATION_PATH}"
            DEPENDS "${SOURCE_PATH}"
            COMMENT "Copying \"${SOURCE_PATH}\" into build directory"
    )

    # Add a random number to the end of the string to avoid problems with
    # duplicate filenames
    set(FILENAME "")
    get_filename_component(FILENAME ${SOURCE_PATH} NAME)
    string(RANDOM LENGTH 4 ALPHABET 0123456789 RANDOMNUMBER)

    ADD_CUSTOM_TARGET(copy_${FILENAME}_${RANDOMNUMBER} DEPENDS "${DESTINATION_PATH}")
    ADD_DEPENDENCIES(${TARGET_TO_DEPEND} copy_${FILENAME}_${RANDOMNUMBER})

endfunction()

##############################################################################
# request-response benchmarks
##############################################################################

set(BENCH_REQUEST_RESPONSE_FOLDER ${PROJECT_SOURCE_DIR}/benchmarks/request_response)

add_executable(bench_request_response_client common/bench_measurer.cpp request_response/bench_request_response_client.cpp)
target_link_libraries(bench_request_response_client vsomeip)

configure_file(
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_local.json.in
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_local.json
        @ONLY)
sign_configuration(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_local.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_local.json
        ${BENCH_CONFIG_OUTPUT}/bench_request_response_client_local.json bench_request_response_client)

configure_file(
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_external.json.in
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_external.json
        @ONLY)
sign_configuration(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_external.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_client_external.json
        ${BENCH_CONFIG_OUTPUT}/bench_request_response_client_external.json bench_request_response_client)

configure_file(
        ${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_slave.sh.in
        ${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_slave.sh
        @ONLY)
copy_to_builddir(${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_slave.sh
        ${BENCH_OUTPUT}/bench_request_response_slave.sh bench_request_response_client)


add_executable(bench_request_response_service common/bench_measurer.cpp request_response/bench_request_response_service.cpp)
target_link_libraries(bench_request_response_service vsomeip)

configure_file(
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_service.json.in
        ${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_service.json
        @ONLY)
sign_configuration(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_service.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_REQUEST_RESPONSE_FOLDER}/conf/bench_request_response_service.json
        ${BENCH_CONFIG_OUTPUT}/bench_request_response_service.json bench_request_response_service)

configure_file(
        ${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_master.sh.in
        ${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_master.sh
        @ONLY)
copy_to_builddir(${BENCH_REQUEST_RESPONSE_FOLDER}/scripts/bench_request_response_master.sh
        ${BENCH_OUTPUT}/bench_request_response_master.sh bench_request_response_service)

##############################################################################
# publish-subscribe benchmarks
##############################################################################

set(BENCH_PUBLISH_SUBSCRIBE_FOLDER ${PROJECT_SOURCE_DIR}/benchmarks/publish_subscribe)

add_executable(bench_publish_subscribe_publisher common/bench_measurer.cpp publish_subscribe/bench_publish_subscribe_publisher.cpp)
target_link_libraries(bench_publish_subscribe_publisher vsomeip)

configure_file(
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_publisher.json.in
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_publisher.json
        @ONLY)
sign_configuration(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_publisher.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_publisher.json
        ${BENCH_CONFIG_OUTPUT}/bench_publish_subscribe_publisher.json bench_publish_subscribe_publisher)

configure_file(
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_slave.sh.in
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_slave.sh
        @ONLY)
copy_to_builddir(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_slave.sh
        ${BENCH_OUTPUT}/bench_publish_subscribe_slave.sh bench_publish_subscribe_publisher)


add_executable(bench_publish_subscribe_subscriber common/bench_measurer.cpp publish_subscribe/bench_publish_subscribe_subscriber.cpp)
target_link_libraries(bench_publish_subscribe_subscriber vsomeip)

configure_file(
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_subscriber.json.in
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_subscriber.json
        @ONLY)
sign_configuration(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_subscriber.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/conf/bench_publish_subscribe_subscriber.json
        ${BENCH_CONFIG_OUTPUT}/bench_publish_subscribe_subscriber.json bench_publish_subscribe_subscriber)

configure_file(
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_master.sh.in
        ${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_master.sh
        @ONLY)
copy_to_builddir(${BENCH_PUBLISH_SUBSCRIBE_FOLDER}/scripts/bench_publish_subscribe_master.sh
        ${BENCH_OUTPUT}/bench_publish_subscribe_master.sh bench_publish_subscribe_subscriber)

##############################################################################
# throughput benchmarks
##############################################################################

set(BENCH_THROUGHPUT_FOLDER ${PROJECT_SOURCE_DIR}/benchmarks/throughput)

add_executable(bench_throughput_publisher common/bench_measurer.cpp throughput/bench_throughput_publisher.cpp)
target_link_libraries(bench_throughput_publisher vsomeip)

configure_file(
        ${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_publisher.json.in
        ${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_publisher.json
        @ONLY)
sign_configuration(${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_publisher.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_publisher.json
        ${BENCH_CONFIG_OUTPUT}/bench_throughput_publisher.json bench_throughput_publisher)

configure_file(
        ${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_slave.sh.in
        ${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_slave.sh
        @ONLY)
copy_to_builddir(${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_slave.sh
        ${BENCH_OUTPUT}/bench_throughput_slave.sh bench_throughput_publisher)


add_executable(bench_throughput_subscriber common/bench_measurer.cpp throughput/bench_throughput_subscriber.cpp)
target_link_libraries(bench_throughput_subscriber vsomeip)

configure_file(
        ${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_subscriber.json.in
        ${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_subscriber.json
        @ONLY)
sign_configuration(${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_subscriber.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_THROUGHPUT_FOLDER}/conf/bench_throughput_subscriber.json
        ${BENCH_CONFIG_OUTPUT}/bench_throughput_subscriber.json bench_throughput_subscriber)

configure_file(
        ${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_master.sh.in
        ${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_master.sh
        @ONLY)
copy_to_builddir(${BENCH_THROUGHPUT_FOLDER}/scripts/bench_throughput_master.sh
        ${BENCH_OUTPUT}/bench_throughput_master.sh bench_throughput_subscriber)

##############################################################################
# session-establishment benchmarks
##############################################################################

set(BENCH_SESSION_ESTABLISHMENT_FOLDER ${PROJECT_SOURCE_DIR}/benchmarks/session_establishment)

add_executable(bench_session_establishment_client common/bench_measurer.cpp session_establishment/bench_session_establishment_client.cpp)
target_link_libraries(bench_session_establishment_client vsomeip)

configure_file(
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_client.json.in
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_client.json
        @ONLY)
sign_configuration(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_client.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_client.json
        ${BENCH_CONFIG_OUTPUT}/bench_session_establishment_client.json bench_session_establishment_client)

configure_file(
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_slave.sh.in
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_slave.sh
        @ONLY)
copy_to_builddir(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_slave.sh
        ${BENCH_OUTPUT}/bench_session_establishment_slave.sh bench_session_establishment_client)


add_executable(bench_session_establishment_service common/bench_measurer.cpp session_establishment/bench_session_establishment_service.cpp)
target_link_libraries(bench_session_establishment_service vsomeip)

configure_file(
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_service.json.in
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_service.json
        @ONLY)
sign_configuration(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_service.json
        ${CRYPTO_CONFIGURATION_SIGNATURE_KEY} ${OPENSSL_LOG} ${CRYPTO_LOCK})
copy_to_builddir(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/conf/bench_session_establishment_service.json
        ${BENCH_CONFIG_OUTPUT}/bench_session_establishment_service.json bench_session_establishment_service)

configure_file(
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_master.sh.in
        ${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_master.sh
        @ONLY)
copy_to_builddir(${BENCH_SESSION_ESTABLISHMENT_FOLDER}/scripts/bench_session_establishment_master.sh
        ${BENCH_OUTPUT}/bench_session_establishment_master.sh bench_session_establishment_service)

##############################################################################
# Add benchmarks to the target build_benchmarks
##############################################################################

add_dependencies(build_benchmarks bench_request_response_client)
add_dependencies(build_benchmarks bench_request_response_service)
add_dependencies(build_benchmarks bench_publish_subscribe_publisher)
add_dependencies(build_benchmarks bench_publish_subscribe_subscriber)
add_dependencies(build_benchmarks bench_throughput_publisher)
add_dependencies(build_benchmarks bench_throughput_subscriber)
add_dependencies(build_benchmarks bench_session_establishment_client)
add_dependencies(build_benchmarks bench_session_establishment_service)

copy_to_builddir(${PROJECT_SOURCE_DIR}/benchmarks/run_runtime_protection_benchmarks.sh
        ${BENCH_OUTPUT}/run_runtime_protection_benchmarks.sh build_benchmarks)
copy_to_builddir(${PROJECT_SOURCE_DIR}/benchmarks/run_throughput_benchmarks.sh
        ${BENCH_OUTPUT}/run_throughput_benchmarks.sh build_benchmarks)
copy_to_builddir(${PROJECT_SOURCE_DIR}/benchmarks/run_session_establishment_benchmarks.sh
        ${BENCH_OUTPUT}/run_session_establishment_benchmarks.sh build_benchmarks)

configure_file(
        ${PROJECT_SOURCE_DIR}/benchmarks/run_iperf3_throughput_benchmarks.sh.in
        ${PROJECT_SOURCE_DIR}/benchmarks/run_iperf3_throughput_benchmarks.sh
        @ONLY)
copy_to_builddir(${PROJECT_SOURCE_DIR}/benchmarks/run_iperf3_throughput_benchmarks.sh
        ${BENCH_OUTPUT}/run_iperf3_throughput_benchmarks.sh build_benchmarks)