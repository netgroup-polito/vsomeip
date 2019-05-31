// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BENCH_SESSION_ESTABLISHMENT_CLIENT_HPP
#define BENCH_SESSION_ESTABLISHMENT_CLIENT_HPP

#include <vsomeip/vsomeip.hpp>
#include "../common/bench_globals.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

class bench_measurer;

class bench_session_establishment_client {
private:
    static constexpr std::uint32_t MAX_SESSION_ESTABLISHMENTS =
            bench_globals::BENCH_SESSION_ESTABLISHMENT_LAST_SERVICE_ID -
            bench_globals::BENCH_SESSION_ESTABLISHMENT_FIRST_SERVICE_ID +
            1;

public:
    bench_session_establishment_client();

    bool init();
    void start();

private:
    void send();
    void run();

    void stop();
    void shutdown_service();

    void request_services(std::unique_lock<std::mutex> &_its_lock);
    void release_services();

    void print_throughput(const bench_measurer &_measurer);

    void on_state(vsomeip::state_type_e _state);
    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available);
    void on_availability_start(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available);

private:
    std::shared_ptr<vsomeip::application> app_;

    bool blocked_;
    bool error_;

    std::uint32_t number_of_requested_services_;
    std::uint32_t number_of_available_services_;
    bool all_services_available_;
    std::array<bool, MAX_SESSION_ESTABLISHMENTS> available_services_;

    std::thread session_establishment_thread_;

    std::mutex start_mutex_;
    std::condition_variable start_cv_;

    std::mutex all_services_available_mutex_;
    std::condition_variable all_services_available_cv_;
};

#endif /* BENCH_SESSION_ESTABLISHMENT_CLIENT_HPP */
