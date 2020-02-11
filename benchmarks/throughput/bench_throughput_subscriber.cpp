// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_throughput_subscriber.hpp"
#include "../common/bench_globals.hpp"

#include <cmath>
#include <iostream>
#include <memory>
#include <sstream>

throughput_subscriber::throughput_subscriber(uint32_t _transfer_size, uint32_t _payload_size_udp,
                                             uint32_t _payload_size_tcp ,bool _use_tcp, bool _shutdown_service_at_end) :
        app_(vsomeip::runtime::get()->create_application()),
        use_tcp_(_use_tcp), shutdown_service_at_end_(_shutdown_service_at_end),
        payload_size_(_use_tcp ? _payload_size_tcp : _payload_size_udp),
        number_of_messages_to_receive_(static_cast<uint32_t>(std::ceil(static_cast<double>(_transfer_size) / payload_size_))),
        number_of_messages_received_(0), stop_(false) {
}

bool throughput_subscriber::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;
        return false;
    }

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                                   std::bind(&throughput_subscriber::on_message, this, std::placeholders::_1));
    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                bench_globals::BENCH_SERVICE_EVENT_TCP_ID,
                                std::bind(&throughput_subscriber::on_message, this, std::placeholders::_1));

    app_->register_state_handler(std::bind(&throughput_subscriber::on_state, this, std::placeholders::_1));

    return true;
}

void throughput_subscriber::start() {
    std::cerr << "Starting..." << std::endl;
    stop_thread_ = std::thread(std::bind(&throughput_subscriber::stop, this));

    app_->start();

    // Join stop thread
    stop_thread_.join();
}

void throughput_subscriber::stop() {

    std::unique_lock<std::mutex> its_lock(stop_mutex_);
    stop_cv_.wait(its_lock, [&] { return stop_; });
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cerr << "Stopping..." << std::endl;
    app_->stop_offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    app_->clear_all_handler();
    app_->stop();
}

void throughput_subscriber::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);

        auto event = use_tcp_
            ? bench_globals::BENCH_SERVICE_EVENT_TCP_ID
            : bench_globals::BENCH_SERVICE_EVENT_UDP_ID;
        auto eventgroup = use_tcp_
            ? bench_globals::BENCH_SERVICE_EVENTGROUP_TCP_ID
            : bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID;
        auto subscription_type = use_tcp_
            ? vsomeip::subscription_type_e::SU_RELIABLE
            : vsomeip::subscription_type_e::SU_UNRELIABLE;

        std::set<vsomeip::eventgroup_t> its_groups{ eventgroup };
        app_->request_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                            event, its_groups, false);

        app_->subscribe(bench_globals::BENCH_SERVICE_SERVICE_ID,
                        bench_globals::BENCH_SERVICE_INSTANCE_ID,
                        eventgroup, vsomeip::DEFAULT_MAJOR, subscription_type);
    }
}

void throughput_subscriber::on_message(const std::shared_ptr<vsomeip::message> &_request) {

    if (++number_of_messages_received_ == number_of_messages_to_receive_) {
        std::shared_ptr<vsomeip::message> its_message = vsomeip::runtime::get()->create_response(_request);
        its_message->set_method(bench_globals::BENCH_SERVICE_METHOD_ID);
        its_message->set_message_type(vsomeip::message_type_e::MT_REQUEST);

        std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> payload_data{static_cast<vsomeip::byte_t>(shutdown_service_at_end_)};
        payload->set_data(payload_data);
        its_message->set_payload(payload);

        app_->send(its_message, true);

        std::lock_guard<std::mutex> its_lock(stop_mutex_);
        stop_ = true;
        stop_cv_.notify_one();
    }
}

int main(int argc, char **argv) {
    std::string tcp_enable("--tcp");
    std::string udp_enable("--udp");
    std::string payload_size_udp_string("--payload-size-udp");
    std::string payload_size_tcp_string("--payload-size-tcp");
    std::string transfer_size_string("--transfer-size");
    std::string disable_shutdown_service("--dont-shutdown-service");
    std::string help("--help");

    bool use_tcp = false;
    bool shutdown_service_at_end = true;

    std::uint32_t payload_size_udp = bench_globals::BENCH_DEFAULT_PAYLOAD_SIZE_UDP;
    std::uint32_t payload_size_tcp = bench_globals::BENCH_DEFAULT_PAYLOAD_SIZE_TCP;
    std::uint32_t transfer_size = bench_globals::BENCH_DEFAULT_MESSAGES_NUMBER;

    int i = 1;
    while (i < argc) {
        if (tcp_enable == argv[i]) {
            use_tcp = true;
        } else if (udp_enable == argv[i]) {
            use_tcp = false;
        } else if (transfer_size_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> transfer_size;
        } else if (payload_size_udp_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> payload_size_udp;
        } else if (payload_size_tcp_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> payload_size_tcp;
        } else if (disable_shutdown_service == argv[i]) {
            shutdown_service_at_end = false;
        } else if (help == argv[i]) {
            std::cerr << "Parameters:\n"
                      << "--tcp: Send messages via TCP\n"
                      << "--udp: Send messages via UDP (default)\n"
                      << "--transfer-size: Total amount of data to tranfer\n"
                      << "--payload-size-udp: Size of the UDP messages to transmit\n"
                      << "--payload-size-tcp: Size of the TCP messages to transmit\n"
                      << "--dont-shutdown-service: Don't shutdown the service upon finishing of the benchmark\n"
                      << "--help: print this help"
                      << std::endl;
        }
        i++;
    }

    throughput_subscriber bench_service(transfer_size, payload_size_udp, payload_size_tcp,
                                        use_tcp, shutdown_service_at_end);
    if (bench_service.init()) {
        bench_service.start();
    }
}