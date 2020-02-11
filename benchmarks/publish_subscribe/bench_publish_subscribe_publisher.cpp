// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_publish_subscribe_publisher.hpp"
#include "../common/bench_globals.hpp"
#include "../common/bench_measurer.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>

bench_publish_subscribe_publisher::bench_publish_subscribe_publisher(uint32_t _number_messages,
                                                                     bool _shutdown_service_at_end) :
        app_(vsomeip::runtime::get()->create_application()),
        number_of_messages_to_send_(_number_messages),
        shutdown_service_at_end_(_shutdown_service_at_end),
        blocked_(false),
        error_(false),
        is_available_(false),
        is_subscribed_(false),
        msg_acknowledged_(false),
        sender_thread_(std::bind(&bench_publish_subscribe_publisher::run, this)) {
}

bool bench_publish_subscribe_publisher::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;

        // Terminate the sender thread
        error_ = true;
        send();
        sender_thread_.join();

        return false;
    }

    app_->register_state_handler(
            std::bind(&bench_publish_subscribe_publisher::on_state, this, std::placeholders::_1));

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_METHOD_ID,
                                   std::bind(&bench_publish_subscribe_publisher::on_message, this,
                                             std::placeholders::_1));

    return true;
}

void bench_publish_subscribe_publisher::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();

    // Join sender thread
    sender_thread_.join();
}

void bench_publish_subscribe_publisher::stop() {
    std::cerr << "Stopping..." << std::endl;

    if (shutdown_service_at_end_) {
        shutdown_service();
    }
    app_->clear_all_handler();
}

void bench_publish_subscribe_publisher::shutdown_service() {
    std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
    app_->notify(bench_globals::BENCH_SERVICE_SERVICE_ID,
                 bench_globals::BENCH_SERVICE_INSTANCE_ID,
                 bench_globals::BENCH_SERVICE_EVENT_ID_SHUTDOWN,
                 payload, true, true);
}

void bench_publish_subscribe_publisher::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->offer_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID);
        app_->offer_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                          bench_globals::BENCH_SERVICE_INSTANCE_ID,
                          bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                          its_groups, false);
        app_->offer_event(bench_globals::BENCH_SERVICE_SERVICE_ID,
                          bench_globals::BENCH_SERVICE_INSTANCE_ID,
                          bench_globals::BENCH_SERVICE_EVENT_ID_SHUTDOWN,
                          its_groups, false);

        app_->register_subscription_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                            bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                            bench_globals::BENCH_SERVICE_EVENTGROUP_UDP_ID,
                                            std::bind(&bench_publish_subscribe_publisher::on_subscription, this,
                                                      std::placeholders::_1, std::placeholders::_2));
    }
}

bool bench_publish_subscribe_publisher::on_subscription(vsomeip::client_t _client, bool _is_subscribed) {

    std::cerr << "Client [" << std::setw(4) << std::setfill('0') << std::hex << _client << "] "
              << (_is_subscribed ? "subscribed." : "UNSUBSCRIBED.") << std::endl;

    if (!is_subscribed_ && _is_subscribed) {
        send();
    }
    is_subscribed_ = _is_subscribed;
    return is_subscribed_;
}


void bench_publish_subscribe_publisher::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    (void) _response;

    // We notify the sender thread every time a message was acknowledged
    std::lock_guard<std::mutex> its_lock(msg_acknowledged_mutex_);
    msg_acknowledged_ = true;
    msg_acknowledged_cv_.notify_one();
}

void bench_publish_subscribe_publisher::send() {
    std::lock_guard<std::mutex> its_lock(send_mutex_);
    blocked_ = true;
    send_cv_.notify_one();
}

void bench_publish_subscribe_publisher::run() {
    std::unique_lock<std::mutex> its_lock(send_mutex_);
    send_cv_.wait(its_lock, [&] { return blocked_; });

    if (error_) {
        return;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::unique_lock<std::mutex> its_lock_ack(msg_acknowledged_mutex_);

    std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
    std::vector<vsomeip::byte_t> payload_data;

    const std::uint32_t max_allowed_payload = 1024;
    for (std::uint32_t payload_size = 1; payload_size <= max_allowed_payload; payload_size *= 2) {
        payload_data.assign(payload_size, bench_globals::BENCH_PAYLOAD_DATA);
        payload->set_data(payload_data);

        bench_measurer bench_measurer;
        bench_measurer.start();
        send_messages(its_lock_ack, payload);
        bench_measurer.stop();
        print_throughput(bench_measurer, payload_size);
    }
    blocked_ = false;

    stop();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    app_->stop();
}

void bench_publish_subscribe_publisher::send_messages(std::unique_lock<std::mutex> &_its_lock,
                                                      const std::shared_ptr<vsomeip::payload> &_payload) {
    for (uint32_t number_of_sent_messages = 0;
         number_of_sent_messages < number_of_messages_to_send_;
         number_of_sent_messages++) {

        app_->notify(bench_globals::BENCH_SERVICE_SERVICE_ID,
                     bench_globals::BENCH_SERVICE_INSTANCE_ID,
                     bench_globals::BENCH_SERVICE_EVENT_UDP_ID,
                     _payload, true, true);

        msg_acknowledged_cv_.wait(_its_lock, [&] { return msg_acknowledged_; });
        msg_acknowledged_ = false;
    }
}

void bench_publish_subscribe_publisher::print_throughput(const bench_measurer &_measurer, std::uint32_t _payload_size) {
    constexpr std::uint32_t usec_per_sec = 1000000;

    bench_measurer::usec_t time_needed = _measurer.get_elapsed_us();
    bench_measurer::usec_t time_per_message = time_needed / number_of_messages_to_send_;

    double calls_per_sec = number_of_messages_to_send_ * (usec_per_sec / static_cast<double>(time_needed));
    double mbyte_per_sec = ((number_of_messages_to_send_ * _payload_size) /
                            (static_cast<double>(time_needed) / usec_per_sec)) / (1024 * 1024);

    std::cout << "[ Publish/Subscribe Benchmark ] :"
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
    std::string numbers_of_messages("--number-of-messages");
    std::string disable_shutdown_service("--dont-shutdown-service");
    std::string help("--help");

    bool shutdown_service_at_end = true;
    std::uint32_t number_messages = bench_globals::BENCH_DEFAULT_MESSAGES_NUMBER;

    int i = 1;
    while (i < argc) {
        if (numbers_of_messages == argv[i] && ++i < argc) {
            std::stringstream converter(argv[i]);
            converter >> number_messages;
        } else if (disable_shutdown_service == argv[i]) {
            shutdown_service_at_end = false;
        } else if (help == argv[i]) {
            std::cerr << "Parameters:\n"
                      << "--number-of-messages: Number of messages to send per payload size iteration\n"
                      << "--dont-shutdown-service: Don't shutdown the service upon finishing of the payload test\n"
                      << "--help: print this help"
                      << std::endl;
        }
        i++;
    }

    bench_publish_subscribe_publisher bench_client(number_messages, shutdown_service_at_end);
    if (bench_client.init()) {
        bench_client.start();
    } else {
        abort();
    }
}
