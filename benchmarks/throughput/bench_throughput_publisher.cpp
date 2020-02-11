// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_throughput_publisher.hpp"
#include "../common/bench_globals.hpp"
#include "../common/bench_measurer.hpp"

#include <cmath>
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>

throughput_publisher::throughput_publisher(
    uint32_t _transfer_size, uint32_t _payload_size_udp, uint32_t _payload_size_tcp) :
        app_(vsomeip::runtime::get()->create_application()),
        payload_size_udp_(_payload_size_udp),
        payload_size_tcp_(_payload_size_tcp),
        transfer_size_(_transfer_size),
        running_(true),
        transmit_(false),
        error_(false),
        is_available_(false),
        is_subscribed_(false),
        all_msg_acknowledged_(false),
        sender_thread_(std::bind(&throughput_publisher::run, this)) {
}

bool throughput_publisher::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;

        // Terminate the sender thread
        error_ = true;
        unlock();
        sender_thread_.join();

        return false;
    }

    app_->register_state_handler(
            std::bind(&throughput_publisher::on_state, this, std::placeholders::_1));

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_METHOD_ID,
                                   std::bind(&throughput_publisher::on_message, this,
                                             std::placeholders::_1));

    return true;
}

void throughput_publisher::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();

    // Join sender thread
    sender_thread_.join();
}

void throughput_publisher::stop() {
    std::cerr << "Stopping..." << std::endl;
    app_->clear_all_handler();
}

void throughput_publisher::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID);
        its_groups.insert(bench_globals::BENCH_SERVICE_EVENTGROUP_TCP_ID);
        app_->offer_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                          bench_globals::BENCH_SERVICE_INSTANCE_ID,
                          bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                          its_groups, false);
        app_->offer_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                          bench_globals::BENCH_SERVICE_INSTANCE_ID,
                          bench_globals::BENCH_SERVICE_EVENT_TCP_ID,
                          its_groups, false);

        app_->register_subscription_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                            bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID,
                                            std::bind(&throughput_publisher::on_subscription, this,
                                                      std::placeholders::_1, std::placeholders::_2, false));

        app_->register_subscription_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                            bench_globals::BENCH_SERVICE_EVENTGROUP_TCP_ID,
                                            std::bind(&throughput_publisher::on_subscription, this,
                                                      std::placeholders::_1, std::placeholders::_2, true));
    }
}

bool throughput_publisher::on_subscription(vsomeip::client_t _client, bool _is_subscribed, bool _use_tcp) {

    std::cerr << "Client [" << std::setw(4) << std::setfill('0') << std::hex << _client << "] "
              << (_is_subscribed ? "subscribed." : "UNSUBSCRIBED.") 
              << " Reliable: " << (_use_tcp ? "true" : "false") << std::endl;

    if (!is_subscribed_ && _is_subscribed) {
        event_ = _use_tcp ? bench_globals::BENCH_SERVICE_EVENT_TCP_ID : bench_globals::BENCH_SERVICE_EVENT_UDP_ID;
        payload_size_ = _use_tcp ? payload_size_tcp_ : payload_size_udp_;
        number_of_messages_to_send_ = static_cast<uint32_t>(std::ceil(
            static_cast<double>(transfer_size_) / payload_size_));
        unlock();
    }
    is_subscribed_ = _is_subscribed;
    return is_subscribed_;
}


void throughput_publisher::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    const auto &payload = _response->get_payload();
    if (payload && payload->get_data() && payload->get_length() >= 1) {
        // Should I stop the service?
        running_ = !static_cast<bool>(*payload->get_data());
    }

    std::lock_guard<std::mutex> its_lock(all_msg_acknowledged_mutex_);
    all_msg_acknowledged_ = true;
    all_msg_acknowledged_cv_.notify_one();
}

void throughput_publisher::unlock() {
    std::lock_guard<std::mutex> its_lock(send_mutex_);
    transmit_ = true;
    send_cv_.notify_one();
}

void throughput_publisher::run() {
    while (running_) {
        std::unique_lock<std::mutex> its_lock(send_mutex_);
        send_cv_.wait(its_lock, [&] { return transmit_; });

        if (error_) {
            return;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::unique_lock<std::mutex> its_lock_ack(all_msg_acknowledged_mutex_);

        std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> payload_data;
        payload_data.assign(payload_size_, bench_globals::BENCH_PAYLOAD_DATA);
        payload->set_data(payload_data);

        bench_measurer bench_measurer;
        bench_measurer.start();
        send_messages(its_lock_ack, payload);
        bench_measurer.stop();
        print_throughput(bench_measurer, payload_size_);

        transmit_ = false;
    }

    stop();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    app_->stop();
}

void throughput_publisher::send_messages(std::unique_lock<std::mutex> &_its_lock,
                                         const std::shared_ptr<vsomeip::payload> &_payload) {
    for (uint32_t number_of_sent_messages_ = 0;
        number_of_sent_messages_ < number_of_messages_to_send_;
        number_of_sent_messages_++) {

        app_->notify(bench_globals::BENCH_SERVICE_SERVICE_ID,
                     bench_globals::BENCH_SERVICE_INSTANCE_ID,
                     event_, _payload, true, true);
    }

    all_msg_acknowledged_cv_.wait(_its_lock, [&] { return all_msg_acknowledged_; });
    all_msg_acknowledged_ = false;
}

void throughput_publisher::print_throughput(const bench_measurer &_measurer, std::uint32_t _payload_size) {
    constexpr std::uint32_t usec_per_sec = 1000000;

    bench_measurer::usec_t time_needed = _measurer.get_elapsed_us();
    bench_measurer::usec_t time_per_message = time_needed / number_of_messages_to_send_;

    double calls_per_sec = number_of_messages_to_send_ * (usec_per_sec / static_cast<double>(time_needed));
    double mbyte_per_sec = ((number_of_messages_to_send_ * _payload_size) /
                            (static_cast<double>(time_needed) / usec_per_sec)) / (1024 * 1024);

    std::cout << "[ Throughput Benchmark ] :"
              << "Payload size [byte]: " << std::dec << std::setw(8) << std::setfill('0') << _payload_size
              << " Messages sent: " << std::dec << std::setw(8) << std::setfill('0') << number_of_messages_to_send_
              << " Elapsed time [usec]: " << std::dec << std::setw(8) << std::setfill('0') << time_needed
              << " Meantime/message [usec]: " << std::dec << std::setw(8) << std::setfill('0') << time_per_message
              << " Calls/sec: " << std::dec << std::setw(8) << std::setfill('0') << std::fixed
              << std::setprecision(1) << calls_per_sec
              << " MiB/sec: " << std::dec << std::setw(8) << std::setfill('0') << std::fixed << std::setprecision(4)
              << mbyte_per_sec
              << " CPU: " << std::dec << std::setw(6) << std::setfill('0') << std::fixed << std::setprecision(2)
              << _measurer.get_cpu_load()
              << std::endl;
}

int main(int argc, char **argv) {
    std::string payload_size_udp_string("--payload-size-udp");
    std::string payload_size_tcp_string("--payload-size-tcp");
    std::string transfer_size_string("--transfer-size");
    std::string help("--help");

    std::uint32_t payload_size_udp = bench_globals::BENCH_DEFAULT_PAYLOAD_SIZE_UDP;
    std::uint32_t payload_size_tcp = bench_globals::BENCH_DEFAULT_PAYLOAD_SIZE_TCP;
    std::uint32_t transfer_size = bench_globals::BENCH_DEFAULT_MESSAGES_NUMBER;

    int i = 1;
    while (i < argc) {
        if (transfer_size_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> transfer_size;
        } else if (payload_size_udp_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> payload_size_udp;
        } else if (payload_size_tcp_string == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> payload_size_tcp;
        } else if (help == argv[i]) {
            std::cerr << "Parameters:\n"
                      << "--transfer-size: Total amount of data to tranfer\n"
                      << "--payload-size-udp: Size of the UDP messages to transmit\n"
                      << "--payload-size-tcp: Size of the TCP messages to transmit\n"
                      << "--help: print this help"
                      << std::endl;
        }
        i++;
    }

    throughput_publisher bench_publish(transfer_size, payload_size_udp, payload_size_tcp);
    if (bench_publish.init()) {
        bench_publish.start();
    } else {
        abort();
    }
}
