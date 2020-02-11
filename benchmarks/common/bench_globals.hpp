// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BENCH_GLOBALS_HPP
#define BENCH_GLOBALS_HPP

#include <vsomeip/vsomeip.hpp>

namespace bench_globals {

static constexpr vsomeip::service_t BENCH_SERVICE_SERVICE_ID = 0x1234;
static constexpr vsomeip::instance_t BENCH_SERVICE_INSTANCE_ID = 0x5678;

static constexpr vsomeip::method_t BENCH_SERVICE_METHOD_ID = 0x4421;
static constexpr vsomeip::method_t BENCH_SERVICE_METHOD_ID_SHUTDOWN = 0x7777;

static constexpr vsomeip::event_t BENCH_SERVICE_EVENT_UDP_ID = 0x8771;
static constexpr vsomeip::event_t BENCH_SERVICE_EVENT_TCP_ID = 0x8772;
static constexpr vsomeip::event_t BENCH_SERVICE_EVENT_ID_SHUTDOWN = 0x8779;
static constexpr vsomeip::eventgroup_t BENCH_SERVICE_EVENTGROUP_UDP_ID = 0x4465;
static constexpr vsomeip::eventgroup_t BENCH_SERVICE_EVENTGROUP_TCP_ID = 0x4466;

static constexpr vsomeip::service_t BENCH_SESSION_ESTABLISHMENT_FIRST_SERVICE_ID = 0x0001;
static constexpr vsomeip::service_t BENCH_SESSION_ESTABLISHMENT_LAST_SERVICE_ID = 0x0100;
static constexpr vsomeip::service_t BENCH_SESSION_ESTABLISHMENT_INSTANCE_ID = 0x0001;

static constexpr vsomeip::byte_t BENCH_PAYLOAD_DATA = 0xDD;
static constexpr std::uint32_t BENCH_DEFAULT_MESSAGES_NUMBER = 1000;
static constexpr std::uint32_t BENCH_DEFAULT_PAYLOAD_SIZE_UDP = 1400;
static constexpr std::uint32_t BENCH_DEFAULT_PAYLOAD_SIZE_TCP = 64*1024;

}

#endif /* BENCH_GLOBALS_HPP */
