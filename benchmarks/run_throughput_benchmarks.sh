#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 9 ]]
then
	echo "Usage: $0 remote_path lib_dir conf_dir log_dir log_name iterations transfer_size payload_size_udp payload_size_tcp"
	exit 1
fi

REMOTE_PATH=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
LOG_NAME=$5
ITERATIONS=$6
TRANSFER_SIZE=$7
PAYLOAD_SIZE_UDP=$8
PAYLOAD_SIZE_TCP=$9

for IDX in `seq 1 ${ITERATIONS}`
do
    LOG_NAME_IDX=${LOG_NAME}_$((${IDX}-1))
    echo "*** Iteration ${IDX} ***"

    ./bench_throughput_master.sh ${REMOTE_PATH} ${LIB_DIR} ${CONF_DIR} ${LOG_DIR} ${LOG_NAME_IDX} \
        ${TRANSFER_SIZE} ${PAYLOAD_SIZE_UDP} ${PAYLOAD_SIZE_TCP}
    sleep 1

    echo
done