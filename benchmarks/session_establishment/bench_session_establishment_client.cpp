// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_session_establishment_client.hpp"
#include "../common/bench_measurer.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>

bench_session_establishment_client::bench_session_establishment_client() :
        app_(vsomeip::runtime::get()->create_application()),
        blocked_(false),
        error_(false),
        number_of_requested_services_(0),
        number_of_available_services_(0),
        all_services_available_(false),
        available_services_{false},
        session_establishment_thread_(std::bind(&bench_session_establishment_client::run, this)) {
}

bool bench_session_establishment_client::init() {
    if (!app_->init()) {
        std::cerr << "Couldn't initialize application" << std::endl;

        // Terminate the sender thread
        error_ = true;
        send();
        session_establishment_thread_.join();

        return false;
    }

    app_->register_state_handler(
            std::bind(&bench_session_establishment_client::on_state, this, std::placeholders::_1));

    app_->register_availability_handler(vsomeip::ANY_SERVICE,
                                        bench_globals::BENCH_SESSION_ESTABLISHMENT_INSTANCE_ID,
                                        std::bind(&bench_session_establishment_client::on_availability, this,
                                                  std::placeholders::_1, std::placeholders::_2,
                                                  std::placeholders::_3));

    app_->register_availability_handler(bench_globals::BENCH_SERVICE_SERVICE_ID,
                                        bench_globals::BENCH_SERVICE_INSTANCE_ID,
                                        std::bind(&bench_session_establishment_client::on_availability_start, this,
                                                  std::placeholders::_1, std::placeholders::_2,
                                                  std::placeholders::_3));

    return true;
}

void bench_session_establishment_client::start() {
    std::cerr << "Starting..." << std::endl;
    app_->start();

    // Join sender thread
    session_establishment_thread_.join();
}

void bench_session_establishment_client::stop() {
    std::cerr << "Stopping..." << std::endl;

    shutdown_service();
    app_->clear_all_handler();
}

void bench_session_establishment_client::shutdown_service() {
    std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request(false);
    request->set_service(bench_globals::BENCH_SERVICE_SERVICE_ID);
    request->set_instance(bench_globals::BENCH_SERVICE_INSTANCE_ID);
    request->set_method(bench_globals::BENCH_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request, true);
}

void bench_session_establishment_client::on_state(vsomeip::state_type_e _state) {
    if (_state == vsomeip::state_type_e::ST_REGISTERED) {
        app_->request_service(bench_globals::BENCH_SERVICE_SERVICE_ID, bench_globals::BENCH_SERVICE_INSTANCE_ID);
    }
}

void bench_session_establishment_client::on_availability(vsomeip::service_t _service,
                                                         vsomeip::instance_t _instance, bool _is_available) {
    std::cerr << "Service [" << std::setw(4) << std::setfill('0') << std::hex << _service << "."
              << std::setw(4) << std::setfill('0') << std::hex << _instance << "] is "
              << (_is_available ? "available." : "NOT available.") << std::endl;

    const std::uint32_t offset = _service - bench_globals::BENCH_SESSION_ESTABLISHMENT_FIRST_SERVICE_ID;
    if (offset < number_of_requested_services_ && _is_available && !available_services_[offset]) {

        number_of_available_services_++;
        available_services_[offset] = true;

        if (number_of_available_services_ == number_of_requested_services_) {
            std::lock_guard<std::mutex> its_lock(all_services_available_mutex_);
            number_of_available_services_ = 0;
            all_services_available_ = true;
            all_services_available_cv_.notify_one();
        }
    }
}

void bench_session_establishment_client::on_availability_start(vsomeip::service_t _service,
                                                               vsomeip::instance_t _instance, bool _is_available) {
    std::cerr << "Service [" << std::setw(4) << std::setfill('0') << std::hex << _service << "."
              << std::setw(4) << std::setfill('0') << std::hex << _instance << "] is "
              << (_is_available ? "available." : "NOT available.") << std::endl;

    if (_is_available) {
        std::lock_guard<std::mutex> its_lock(start_mutex_);
        blocked_ = true;
        start_cv_.notify_one();
    }
}

void bench_session_establishment_client::send() {
    std::lock_guard<std::mutex> its_lock(start_mutex_);
    blocked_ = true;
    start_cv_.notify_one();
}

void bench_session_establishment_client::run() {
    std::unique_lock<std::mutex> its_lock(start_mutex_);
    start_cv_.wait(its_lock, [&] { return blocked_; });

    if (error_) {
        return;
    }

    std::unique_lock<std::mutex> its_lock_ack(all_services_available_mutex_);

    for (number_of_requested_services_ = 1;
         number_of_requested_services_ <= MAX_SESSION_ESTABLISHMENTS;
         number_of_requested_services_ *= 2) {

        std::this_thread::sleep_for(std::chrono::seconds(1));

        bench_measurer bench_measurer;
        bench_measurer.start();
        request_services(its_lock_ack);
        bench_measurer.stop();
        print_throughput(bench_measurer);

        release_services();
    }
    blocked_ = false;

    stop();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    app_->stop();
}

void bench_session_establishment_client::request_services(std::unique_lock<std::mutex> &_its_lock) {
    for (vsomeip::service_t service_offset = 0; service_offset < number_of_requested_services_; service_offset++) {
        auto service_id = static_cast<vsomeip::service_t>(
                bench_globals::BENCH_SESSION_ESTABLISHMENT_FIRST_SERVICE_ID + service_offset);
        app_->request_service(service_id, bench_globals::BENCH_SESSION_ESTABLISHMENT_INSTANCE_ID);
    }

    all_services_available_cv_.wait(_its_lock, [&] { return all_services_available_; });
    all_services_available_ = false;
    available_services_.fill(false);
}

void bench_session_establishment_client::release_services() {
    for (vsomeip::service_t service_offset = 0; service_offset < number_of_requested_services_; service_offset++) {
        auto service_id = static_cast<vsomeip::service_t>(
                bench_globals::BENCH_SESSION_ESTABLISHMENT_FIRST_SERVICE_ID + service_offset);
        app_->release_service(service_id, bench_globals::BENCH_SESSION_ESTABLISHMENT_INSTANCE_ID);
    }
}


void bench_session_establishment_client::print_throughput(const bench_measurer &_measurer) {
    constexpr std::uint32_t usec_per_sec = 1000000;

    bench_measurer::usec_t time_needed = _measurer.get_elapsed_us();
    bench_measurer::usec_t time_per_session_establishment = time_needed / number_of_requested_services_;
    double calls_per_sec = number_of_requested_services_ * (usec_per_sec / static_cast<double>(time_needed));

    std::cout << "[ Session Establishment Benchmark ] :"
              << " Session establishments: " << std::dec << std::setw(4) << std::setfill('0')
              << number_of_requested_services_
              << " Elapsed time [usec]: " << std::dec << std::setw(8) << std::setfill('0') << time_needed
              << " Meantime/session establishment [usec]: " << std::dec << std::setw(8) << std::setfill('0')
              << time_per_session_establishment
              << " Calls/sec: " << std::dec << std::setw(8) << std::setfill('0') << std::fixed
              << std::setprecision(1) << calls_per_sec
              << " CPU: " << std::dec << std::setw(6) << std::setfill('0') << std::fixed << std::setprecision(2)
              << _measurer.get_cpu_load()
              << std::endl;
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    bench_session_establishment_client bench_client;
    if (bench_client.init()) {
        bench_client.start();
    } else {
        abort();
    }
}
