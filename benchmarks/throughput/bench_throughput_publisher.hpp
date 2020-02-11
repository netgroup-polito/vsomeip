// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef THROUGHPUT_PUBLISHER_HPP
#define THROUGHPUT_PUBLISHER_HPP

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

class bench_measurer;

class throughput_publisher {
public:
    throughput_publisher(uint32_t _transfer_size, uint32_t _payload_size_udp, uint32_t _payload_size_tcp);

    bool init();
    void start();

private:
    void unlock();
    void run();

    void stop();
    void shutdown_service();

    void print_throughput(const bench_measurer &_measurer, std::uint32_t _payload_size);

    void send_messages(std::unique_lock<std::mutex> &_its_lock,
                       const std::shared_ptr<vsomeip::payload> &_payload);

    void on_state(vsomeip::state_type_e _state);
    bool on_subscription(vsomeip::client_t _client, bool _is_subscribed, bool _use_tcp);
    void on_message(const std::shared_ptr<vsomeip::message> &_response);

private:
    std::shared_ptr<vsomeip::application> app_;

    const std::uint32_t payload_size_udp_;
    const std::uint32_t payload_size_tcp_;
    const std::uint32_t transfer_size_;

    vsomeip::event_t event_;
    std::uint32_t payload_size_;
    std::uint32_t number_of_messages_to_send_;

    bool running_;
    bool transmit_;
    bool error_;
    bool is_available_;
    bool is_subscribed_;

    bool all_msg_acknowledged_;

    std::thread sender_thread_;

    std::mutex send_mutex_;
    std::condition_variable send_cv_;

    std::mutex all_msg_acknowledged_mutex_;
    std::condition_variable all_msg_acknowledged_cv_;
};

#endif /* THROUGHPUT_PUBLISHER_HPP */
