#!/bin/bash
# Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -ne 4 ]]
then
	echo "Usage: $0 dir lib_dir conf_dir log_dir"
	exit 1
fi

DIR=$1
LIB_DIR=$2
CONF_DIR=$3
LOG_DIR=$4

cd "${DIR}"
export LD_LIBRARY_PATH="${LIB_DIR}"

mkdir -p "${LOG_DIR}"

export VSOMEIP_APPLICATION_NAME=bench_publish_subscribe_subscriber
export VSOMEIP_CONFIGURATION="${CONF_DIR}/bench_publish_subscribe_subscriber.json"

##### UDP Communication #####
./bench_publish_subscribe_subscriber 2>> ${LOG_DIR}/bench_publish_subscribe_subscriber_stderr
