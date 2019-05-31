// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BENCH_MEASURER_HPP
#define BENCH_MEASURER_HPP

#include <cstdint>
#include <chrono>

class bench_measurer {
public:
    using usec_t = std::uint64_t;

    bench_measurer();

    void start();
    void stop();

    usec_t get_elapsed_us() const;
    double get_cpu_load() const;

private:
    std::uint64_t read_proc_stat();
    std::uint64_t read_proc_pid_stat();

private:
    std::chrono::time_point<std::chrono::steady_clock> time_point_start;
    std::chrono::time_point<std::chrono::steady_clock> time_point_stop;

    std::uint64_t jiffies_cpu_start_;
    std::uint64_t jiffies_cpu_stop_;

    std::uint64_t jiffies_process_start;
    std::uint64_t jiffies_process_stop;

    usec_t elapsed_us_;
    double cpu_load_pid_;
};

#endif /* BENCH_MEASURER_HPP */
