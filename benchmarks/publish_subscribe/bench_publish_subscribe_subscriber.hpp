// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BENCH_PUBLISH_SUBSCRIBE_SERVICE_HPP
#define BENCH_PUBLISH_SUBSCRIBE_SERVICE_HPP

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

class bench_publish_subscribe_subscriber {
public:
    bench_publish_subscribe_subscriber();

    bool init();
    void start();

private:
    void stop();

    void on_state(vsomeip::state_type_e _state);
    void on_message(const std::shared_ptr<vsomeip::message> &_request);
    void on_message_shutdown(const std::shared_ptr<vsomeip::message> &_request);

private:
    std::shared_ptr<vsomeip::application> app_;
};

#endif /* BENCH_PUBLISH_SUBSCRIBE_SERVICE_HPP */
