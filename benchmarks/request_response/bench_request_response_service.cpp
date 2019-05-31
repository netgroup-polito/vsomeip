// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_request_response_service.hpp"
#include "../common/bench_globals.hpp"

#include <iostream>
#include <memory>

bench_request_response_service::bench_request_response_service() :
        app_(vsomeip::runtime::get()->create_application()) {
}

bool bench_request_response_service::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;
        return false;
    }

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_METHOD_ID,
                                   std::bind(&bench_request_response_service::on_message, this, std::placeholders::_1));

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_METHOD_ID_SHUTDOWN,
                                   std::bind(&bench_request_response_service::on_message_shutdown, this,
                                             std::placeholders::_1));

    app_->register_state_handler(std::bind(&bench_request_response_service::on_state, this, std::placeholders::_1));

    return true;
}

void bench_request_response_service::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();
}

void bench_request_response_service::stop() {
    std::cerr << "Stopping..." << std::endl;
    app_->stop_offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    app_->clear_all_handler();
    app_->stop();
}

void bench_request_response_service::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    }
}

void bench_request_response_service::on_message(const std::shared_ptr<vsomeip::message> &_request) {
    std::shared_ptr<vsomeip::message> its_response = vsomeip::runtime::get()->create_response(_request);
    app_->send(its_response, true);
}

void bench_request_response_service::on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request) {
    (void) _request;

    std::cerr << "Shutdown method was called, going down now." << std::endl;
    stop();
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    bench_request_response_service bench_service;
    if (bench_service.init()) {
        bench_service.start();
    }
}
