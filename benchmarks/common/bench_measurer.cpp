// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "bench_measurer.hpp"

#include <fstream>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstdio>

#include <sys/types.h>
#include <unistd.h>

bench_measurer::bench_measurer() :
        jiffies_cpu_start_(0), jiffies_cpu_stop_(0),
        jiffies_process_start(0), jiffies_process_stop(0),
        elapsed_us_(0), cpu_load_pid_(0) {
}

void bench_measurer::start() {
    time_point_start = std::chrono::steady_clock::now();
    jiffies_cpu_start_ = read_proc_stat();
    jiffies_process_start = read_proc_pid_stat();
}

void bench_measurer::stop() {
    time_point_stop = std::chrono::steady_clock::now();
    jiffies_cpu_stop_ = read_proc_stat();
    jiffies_process_stop = read_proc_pid_stat();

    if (jiffies_cpu_stop_ < jiffies_cpu_start_ || jiffies_process_stop < jiffies_process_start) {
        std::cerr << "Overflow of values in procfs occurred, can't calculate load" << std::endl;
        exit(0);
    }

    elapsed_us_ = static_cast<bench_measurer::usec_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(time_point_stop - time_point_start).count());

    auto jiffies_cpu = static_cast<double>(jiffies_cpu_stop_ - jiffies_cpu_start_);
    auto jiffies_process = static_cast<double>(jiffies_process_stop - jiffies_process_start);
    cpu_load_pid_ = 100.0 * jiffies_process / jiffies_cpu;
}

bench_measurer::usec_t bench_measurer::get_elapsed_us() const {
    return elapsed_us_;
}

double bench_measurer::get_cpu_load() const {
    return cpu_load_pid_;
}


std::uint64_t bench_measurer::read_proc_pid_stat() {

    FILE *file = std::fopen("/proc/self/stat", "r");
    if (!file) {
        std::perror(std::string("Failed to open /proc/self/stat").c_str());
        exit(1);
    }

    // see Table 1-4 Contents of the stat files (as of 2.6.30-rc7)
    // at https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/Documentation/filesystems/proc.txt?id=refs/tags/v3.10.98
    // and man proc (for conversion specifier)
    std::uint64_t utime(0);
    std::uint64_t stime(0);
    std::int64_t cutime(0);
    std::int64_t cstime(0);
    if (std::fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                          "%lu %lu %ld %ld", // utime, stime, cutime, cstime
                    &utime, &stime, &cutime, &cstime) == EOF) {
        std::cerr << "Failed to read /proc/self/stat" << std::endl;
        exit(1);
    }
    std::fclose(file);

    return utime + stime + cutime + cstime;
}

std::uint64_t bench_measurer::read_proc_stat() {
    FILE *file = std::fopen("/proc/stat", "r");
    if (!file) {
        std::perror("Failed to open /proc/stat");
        exit(1);
    }

    // see 1.8 Miscellaneous kernel statistics in /proc/stat
    // at https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/Documentation/filesystems/proc.txt?id=refs/tags/v3.10.98
    std::uint64_t user(0);
    std::uint64_t nice(0);
    std::uint64_t system(0);
    std::uint64_t idle(0);
    std::uint64_t iowait(0);
    std::uint64_t irq(0);
    std::uint64_t softirq(0);
    std::uint64_t steal(0);
    std::uint64_t guest(0);
    std::uint64_t guest_nice(0);
    if (std::fscanf(file, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
                    &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) == EOF) {
        std::cerr << "Failed to read /proc/stat" << std::endl;
        exit(1);
    }
    std::fclose(file);

    return user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
}
