#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 5 ]]
then
	echo "Usage: $0 remote_path lib_dir conf_dir log_dir iterations"
	exit 1
fi

REMOTE_PATH=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4
ITERATIONS=$5

for IDX in `seq 1 ${ITERATIONS}`
do
    LOG_NAME_IDX=$((${IDX}-1))
    echo "*** Iteration ${IDX} ***"

    ./bench_session_establishment_master.sh ${REMOTE_PATH} ${LIB_DIR} ${CONF_DIR} ${LOG_DIR} ${LOG_NAME_IDX}
    sleep 1

    echo
done
