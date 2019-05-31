// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_request_response_client.hpp"
#include "../common/bench_globals.hpp"
#include "../common/bench_measurer.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>

bench_request_response_client::bench_request_response_client(uint32_t _number_messages, bool _use_tcp,
                                                             bool _call_service_sync, bool _shutdown_service_at_end) :
        app_(vsomeip::runtime::get()->create_application()),
        request_(vsomeip::runtime::get()->create_request(_use_tcp)),
        number_of_messages_to_send_(_number_messages),
        call_service_sync_(_call_service_sync),
        shutdown_service_at_end_(_shutdown_service_at_end),
        blocked_(false),
        error_(false),
        is_available_(false),
        number_of_sent_messages_(0),
        number_of_sent_messages_total_(0),
        number_of_acknowledged_messages_(0),
        all_msg_acknowledged_(false),
        sender_thread_(std::bind(&bench_request_response_client::run, this)) {
}

bool bench_request_response_client::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;

        // Terminate the sender thread
        error_ = true;
        send();
        sender_thread_.join();

        return false;
    }

    app_->register_state_handler(
            std::bind(&bench_request_response_client::on_state, this, std::placeholders::_1));

    app_->register_message_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                   bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                   bench_globals::BENCH_SERVICE_METHOD_ID,
                                   std::bind(&bench_request_response_client::on_message, this,
                                             std::placeholders::_1));

    app_->register_availability_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                        bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                        std::bind(&bench_request_response_client::on_availability, this,
                                                  std::placeholders::_1, std::placeholders::_2,
                                                  std::placeholders::_3));

    return true;
}

void bench_request_response_client::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();

    // Join sender thread
    sender_thread_.join();
}

void bench_request_response_client::stop() {
    std::cerr << "Stopping..." << std::endl;

    if (shutdown_service_at_end_) {
        shutdown_service();
    }
    app_->clear_all_handler();
}

void bench_request_response_client::shutdown_service() {
    request_->set_service(bench_globals::BENCH_SERVICE_SERVICE_ID);
    request_->set_instance(bench_globals::BENCH_SERVICE_INSTANCE_ID);
    request_->set_method(bench_globals::BENCH_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request_, true);
}

void bench_request_response_client::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    }
}

void bench_request_response_client::on_availability(vsomeip::service_t _service,
                                                    vsomeip::instance_t _instance, bool _is_available) {
    std::cerr << "Service [" << std::setw(4) << std::setfill('0') << std::hex
              << _service << "." << _instance << "] is "
              << (_is_available ? "available." : "NOT available.") << std::endl;

    if (is_available_ && !_is_available) {
        is_available_ = false;
    } else if (_is_available && !is_available_) {
        is_available_ = true;
        send();
    }
}

void bench_request_response_client::on_message(const std::shared_ptr<vsomeip::message> &_response) {
    (void) _response;
    number_of_acknowledged_messages_++;

    if (call_service_sync_) {
        // We notify the sender thread every time a message was acknowledged
        {
            std::lock_guard<std::mutex> its_lock(all_msg_acknowledged_mutex_);
            all_msg_acknowledged_ = true;
        }
        all_msg_acknowledged_cv_.notify_one();
    } else {
        // We notify the sender thread only if all sent messages have been acknowledged
        if (number_of_acknowledged_messages_ == number_of_messages_to_send_) {
            std::lock_guard<std::mutex> its_lock(all_msg_acknowledged_mutex_);
            number_of_acknowledged_messages_ = 0;
            all_msg_acknowledged_ = true;
            all_msg_acknowledged_cv_.notify_one();
        }
    }
}

void bench_request_response_client::send() {
    std::lock_guard<std::mutex> its_lock(send_mutex_);
    blocked_ = true;
    send_cv_.notify_one();
}

void bench_request_response_client::run() {
    std::unique_lock<std::mutex> its_lock(send_mutex_);
    send_cv_.wait(its_lock, [&] { return blocked_; });

    if (error_) {
        return;
    }

    std::unique_lock<std::mutex> its_lock_ack(all_msg_acknowledged_mutex_);

    request_->set_service(bench_globals::BENCH_SERVICE_SERVICE_ID);
    request_->set_instance(bench_globals::BENCH_SERVICE_INSTANCE_ID);
    request_->set_method(bench_globals::BENCH_SERVICE_METHOD_ID);

    std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
    std::vector<vsomeip::byte_t> payload_data;

    const std::uint32_t max_allowed_payload = 1024;
    for (std::uint32_t payload_size = 1; payload_size <= max_allowed_payload; payload_size *= 2) {
        payload_data.assign(payload_size, bench_globals::BENCH_PAYLOAD_DATA);
        payload->set_data(payload_data);
        request_->set_payload(payload);

        bench_measurer bench_measurer;
        bench_measurer.start();
        call_service_sync_ ? send_messages_sync(its_lock_ack) : send_messages_async(its_lock_ack);
        bench_measurer.stop();
        print_throughput(bench_measurer, payload_size);
    }
    blocked_ = false;

    stop();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    app_->stop();
}

void bench_request_response_client::send_messages_sync(std::unique_lock<std::mutex> &_its_lock) {
    for (number_of_sent_messages_ = 0;
         number_of_sent_messages_ < number_of_messages_to_send_;
         number_of_sent_messages_++, number_of_sent_messages_total_++) {

        app_->send(request_, true);
        all_msg_acknowledged_cv_.wait(_its_lock, [&] { return all_msg_acknowledged_; });
        all_msg_acknowledged_ = false;
    }
}

void bench_request_response_client::send_messages_async(std::unique_lock<std::mutex> &_its_lock) {
    for (number_of_sent_messages_ = 0;
         number_of_sent_messages_ < number_of_messages_to_send_;
         number_of_sent_messages_++, number_of_sent_messages_total_++) {

        app_->send(request_, true);
    }

    all_msg_acknowledged_cv_.wait(_its_lock, [&] { return all_msg_acknowledged_; });
    all_msg_acknowledged_ = false;
}

void bench_request_response_client::print_throughput(const bench_measurer &_measurer, std::uint32_t _payload_size) {
    constexpr std::uint32_t usec_per_sec = 1000000;

    bench_measurer::usec_t time_needed = _measurer.get_elapsed_us();
    bench_measurer::usec_t time_per_message = time_needed / number_of_sent_messages_;

    double calls_per_sec = number_of_sent_messages_ * (usec_per_sec / static_cast<double>(time_needed));
    double mbyte_per_sec = ((number_of_sent_messages_ * _payload_size) /
                            (static_cast<double>(time_needed) / usec_per_sec)) / (1024 * 1024);

    std::cout << "[ Request/Response Benchmark ] :"
              << "Payload size [byte]: " << std::dec << std::setw(8) << std::setfill('0') << _payload_size
              << " Messages sent: " << std::dec << std::setw(8) << std::setfill('0') << number_of_sent_messages_
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
    std::string tcp_enable("--tcp");
    std::string udp_enable("--udp");
    std::string sync_enable("--sync");
    std::string async_enable("--async");
    std::string numbers_of_messages("--number-of-messages");
    std::string disable_shutdown_service("--dont-shutdown-service");
    std::string help("--help");

    bool use_tcp = false;
    bool call_service_sync = true;
    bool shutdown_service_at_end = true;
    std::uint32_t number_messages = bench_globals::BENCH_DEFAULT_MESSAGES_NUMBER;

    int i = 1;
    while (i < argc) {
        if (tcp_enable == argv[i]) {
            use_tcp = true;
        } else if (udp_enable == argv[i]) {
            use_tcp = false;
        } else if (sync_enable == argv[i]) {
            call_service_sync = true;
        } else if (async_enable == argv[i]) {
            call_service_sync = false;
        } else if (numbers_of_messages == argv[i]) {
            i++;
            std::stringstream converter(argv[i]);
            converter >> number_messages;
        } else if (disable_shutdown_service == argv[i]) {
            shutdown_service_at_end = false;
        } else if (help == argv[i]) {
            std::cerr << "Parameters:\n"
                      << "--tcp: Send messages via TCP\n"
                      << "--udp: Send messages via UDP (default)\n"
                      << "--sync: Wait for acknowledge before sending next message (default)\n"
                      << "--async: Send multiple messages w/o waiting for acknowledge of service\n"
                      << "--number-of-messages: Number of messages to send per payload size iteration\n"
                      << "--dont-shutdown-service: Don't shutdown the service upon finishing of the payload test\n"
                      << "--help: print this help"
                      << std::endl;
        }
        i++;
    }

    bench_request_response_client bench_client(number_messages, use_tcp, call_service_sync, shutdown_service_at_end);
    if (bench_client.init()) {
        bench_client.start();
    } else {
        abort();
    }
}
