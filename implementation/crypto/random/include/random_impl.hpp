// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_RANDOM_IMPL_HPP
#define VSOMEIP_RANDOM_IMPL_HPP

#include <mutex>
#include "random.hpp"

namespace vsomeip {

/**
 * \brief The actual implementation of the vsomeip::random interface.
 */
class random_impl : public random {

public:
    /**
     * \brief Returns the singleton instance used to access
     * the provided functions.
     */
    static random& get_instance()
    {
        static random_impl instance;
        return instance;
    }

public:
    random_impl(const random_impl &) = delete;

    random_impl &operator=(const random_impl &) = delete;

    ~random_impl() override = default;

    secure_vector<byte_t> randomize(size_t _size) override;

    bool randomize(std::vector<byte_t> &_buffer) override;

    bool randomize(secure_vector<byte_t> &_buffer) override;

    bool randomize(byte_t *_buffer, size_t _size) override;

private:
    random_impl() = default;

private:
    std::mutex random_mutex_;
};

} // namespace vsomeip


#endif //VSOMEIP_RANDOM_IMPL_HPP
