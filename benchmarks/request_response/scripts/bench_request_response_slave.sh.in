#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 7 ]]
then
	echo "Usage: $0 dir lib_dir conf_dir log_dir log_name messages_to_send sync"
	exit 1
fi

DIR=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
LOG_NAME=$5
MESSAGES=$6
SYNC=$7

cd "${DIR}"
export LD_LIBRARY_PATH="${LIB_DIR}"

mkdir -p "${LOG_DIR}"

export VSOMEIP_APPLICATION_NAME=bench_request_response_client_external
export VSOMEIP_CONFIGURATION="${CONF_DIR}/bench_request_response_client_external.json"

##### UDP Communication #####
./bench_request_response_client --udp --${SYNC} --number-of-messages ${MESSAGES} --dont-shutdown-service \
    > ${LOG_DIR}/${SYNC}_${LOG_NAME}_udp \
    2>> ${LOG_DIR}/bench_request_response_client_udp_stderr

sleep 2

##### TCP Communication #####
./bench_request_response_client --tcp --${SYNC} --number-of-messages ${MESSAGES} \
    > ${LOG_DIR}/${SYNC}_${LOG_NAME}_tcp \
    2>> ${LOG_DIR}/bench_request_response_client_tcp_stderr
