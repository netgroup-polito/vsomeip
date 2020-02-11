// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_publish_subscribe_subscriber.hpp"
#include "../common/bench_globals.hpp"

#include <iostream>
#include <memory>

bench_publish_subscribe_subscriber::bench_publish_subscribe_subscriber() :
        app_(vsomeip::runtime::get()->create_application()) {
}

bool bench_publish_subscribe_subscriber::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;
        return false;
    }

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                                   std::bind(&bench_publish_subscribe_subscriber::on_message, this, std::placeholders::_1));

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_EVENT_ID_SHUTDOWN,
                                   std::bind(&bench_publish_subscribe_subscriber::on_message_shutdown, this,
                                             std::placeholders::_1));

    app_->register_state_handler(std::bind(&bench_publish_subscribe_subscriber::on_state, this, std::placeholders::_1));

    return true;
}

void bench_publish_subscribe_subscriber::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();
}

void bench_publish_subscribe_subscriber::stop() {
    std::cerr << "Stopping..." << std::endl;
    app_->stop_offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    app_->clear_all_handler();
    app_->stop();
}

void bench_publish_subscribe_subscriber::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID);
        app_->request_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                            bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                            its_groups, false);
        app_->request_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                            bench_globals::BENCH_SERVICE_EVENT_ID_SHUTDOWN,
                            its_groups, false);

        app_->subscribe(bench_globals::BENCH_SERVICE_SERVICE_ID,
                        bench_globals::BENCH_SERVICE_INSTANCE_ID,
                        bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID,
                        vsomeip::DEFAULT_MAJOR, vsomeip::subscription_type_e::SU_UNRELIABLE);
    }
}

void bench_publish_subscribe_subscriber::on_message(const std::shared_ptr<vsomeip::message> &_request) {
    std::shared_ptr<vsomeip::message> its_response = vsomeip::runtime::get()->create_response(_request);
    its_response->set_method(bench_globals::BENCH_SERVICE_METHOD_ID);
    its_response->set_message_type(vsomeip::message_type_e::MT_REQUEST);
    app_->send(its_response, true);
}

void bench_publish_subscribe_subscriber::on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request) {
    (void) _request;

    std::cerr << "Shutdown method was called, going down now." << std::endl;
    stop();
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    bench_publish_subscribe_subscriber bench_service;
    if (bench_service.init()) {
        bench_service.start();
    }
}
