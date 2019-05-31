// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BENCH_REQUEST_RESPONSE_CLIENT_HPP
#define BENCH_REQUEST_RESPONSE_CLIENT_HPP

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

class bench_measurer;

class bench_request_response_client {
public:
    bench_request_response_client(uint32_t _number_messages, bool _use_tcp,
                                  bool _call_service_sync, bool _shutdown_service_at_end);

    bool init();
    void start();


private:
    void send();
    void run();

    void stop();
    void shutdown_service();

    void print_throughput(const bench_measurer &_measurer, std::uint32_t _payload_size);

    void send_messages_sync(std::unique_lock<std::mutex> &_its_lock);
    void send_messages_async(std::unique_lock<std::mutex> &_its_lock);

    void on_state(vsomeip::state_type_e _state);
    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available);
    void on_message(const std::shared_ptr<vsomeip::message> &_response);

private:
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;

    const std::uint32_t number_of_messages_to_send_;
    const bool call_service_sync_;
    const bool shutdown_service_at_end_;

    bool blocked_;
    bool error_;
    bool is_available_;

    std::uint32_t number_of_sent_messages_;
    std::uint32_t number_of_sent_messages_total_;
    std::uint32_t number_of_acknowledged_messages_;
    bool all_msg_acknowledged_;

    std::thread sender_thread_;

    std::mutex send_mutex_;
    std::condition_variable send_cv_;

    std::mutex all_msg_acknowledged_mutex_;
    std::condition_variable all_msg_acknowledged_cv_;
};

#endif /* BENCH_REQUEST_RESPONSE_CLIENT_HPP */
