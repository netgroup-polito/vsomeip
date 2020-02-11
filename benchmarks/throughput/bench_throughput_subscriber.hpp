// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef THROUGHPUT_SERVICE_HPP
#define THROUGHPUT_SERVICE_HPP

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

class throughput_subscriber {
public:
    throughput_subscriber(uint32_t _transfer_size, uint32_t _payload_size_udp, uint32_t _payload_size_tcp,
                          bool _use_tcp, bool _shutdown_service_at_end);

    bool init();
    void start();

private:
    void stop();

    void on_state(vsomeip::state_type_e _state);
    void on_message(const std::shared_ptr<vsomeip::message> &_request);

private:
    std::shared_ptr<vsomeip::application> app_;

    const bool use_tcp_;
    const bool shutdown_service_at_end_;
    const uint32_t payload_size_;
    const uint32_t number_of_messages_to_receive_;

    uint32_t number_of_messages_received_;

    std::thread stop_thread_;
    std::mutex stop_mutex_;
    std::condition_variable stop_cv_;
    bool stop_;
};

#endif /* THROUGHPUT_SERVICE_HPP */
