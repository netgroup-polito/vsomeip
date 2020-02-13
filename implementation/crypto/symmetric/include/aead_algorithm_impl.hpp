// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_OPENSSL_AUTHENTICATED_ENCRYPTION_HPP
#define VSOMEIP_OPENSSL_AUTHENTICATED_ENCRYPTION_HPP

#include <map>

#include "mac_algorithm.hpp"
#include "aead_algorithm.hpp"
#include "../../common/include/algorithms.hpp"
#include "../../common/include/crypto_types.hpp"

namespace vsomeip {

/**
 * \brief Base class implementing the vsomeip::mac_algorithm and vsomeip::aead_algorithm interfaces.
 *
 * This class provides an implementation of the two basic interfaces, by exploiting
 * the OpenSSL library for the actual execution of the chosen cryptographic algorithm.
 * It is meant to abstract stream AEAD algorithms capable of operating also in
 * authentication-only mode (mac_algorithm interface). Additional classes are expected
 * to derive from this one, partially general, to represent a single algorithm and
 * hide the implementation-dependent parameters still exposed. For optimization purposes,
 * the IV value is fixed to be 12 bytes long and made up of two initial zero bytes, the
 * crypto_instance_id (two bytes) and an eight bytes counter.
 */
class aead_algorithm_impl : public mac_algorithm, public aead_algorithm {
protected:
    /// \brief The length of the IV in bits.
    const static size_t IV_LENGTH_BIT = 96;
    /// \brief The length of the IV in bytes.
    const static size_t IV_LENGTH = IV_LENGTH_BIT / 8;

    /// \brief The data type representing a part of the counter.
    using counter_element_t = uint32_t;
    /// \brief The data type representing the counter (64 bits) used as part of the IV and for replay protection.
    using counter_t = std::pair<counter_element_t, counter_element_t>;
    /// \brief The data type used to represent the difference between two counter_t objects.
    using counter_diff_t = int32_t;

    /**
     * \brief The data type used to store the information necessary for replay protection
     * according to a sliding window strategy.
     *
     * In particular, it memorizes the last value of the counter that has been detected
     * and a bitmap, storing whether the previous values of the counter have also been
     * received or not. This strategy is adopted since messages can be transported using
     * an both reliable and unreliable protocol, thus having the possibility of lost or
     * reordered packets.
     */
    using counter_history_t = std::pair<counter_t, uint32_t>;
    /// \brief The data type used to represent an index within the sliding window.
    using counter_history_idx_t = uint8_t;

    /// \brief The number of consecutive counters that are represented by the sliding window.
    const static counter_diff_t MAX_HISTORY_LENGTH = std::numeric_limits<counter_history_t::second_type>::digits;

protected:
    /**
     * Constructs a new instance of this class.
     *
     * @param _cipher the OpenSSL object identifying the chosen cryptographic algorithm.
     * @param _key the symmetric key used by the actual cryptographic functions.
     * @param _tag_length the length in bytes of the MAC.
     * @param _instance_id the ID associated to the current instance (used to construct the IV).
     */
    aead_algorithm_impl(const EVP_CIPHER *_cipher, secure_vector<byte_t> _key,
                        size_t _tag_length, crypto_instance_t _instance_id);

public:
    aead_algorithm_impl(const aead_algorithm_impl &) = delete;

    aead_algorithm_impl &operator=(const aead_algorithm_impl &) = delete;

    ~aead_algorithm_impl() override;

    bool sign(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) override;

    bool verify(const byte_t *_data, size_t _size, std::vector<byte_t> &_output) override;

    bool encipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                  std::vector<byte_t> &_output) override;

    bool decipher(const byte_t *_data, size_t _size, size_t _associated_data_length,
                  std::vector<byte_t> &_output) override;

    size_t get_signed_output_length(size_t _input_length) const override;

    size_t get_verified_output_length(size_t _input_length) const override;

    size_t get_enciphered_output_length(size_t _input_length) const override;

    size_t get_deciphered_output_length(size_t _input_length) const override;

    bool add_allowed_peer(crypto_instance_t _instance_id) override;

protected:
    /**
     * \brief Increments the initialization vector, which needs to be different
     * for each encryption/signature.
     *
     * @return a value indicating whether the operation succeeded or the maximum
     * value has been reached.
     */
    bool increment_encipher_iv();

    /**
     * \brief Validates and extracts the components of the IV, which are used
     * for replay protection.
     *
     * In particular, the replay protection is provided by exploiting the IV,
     * already necessary for the correct operation of the cryptographic algorithm.
     * It is composed by two parts: the initial ID, which identifies the instance
     * performing the operation, and the counter, which is incremented on every
     * new operation. This function extracts the two pieces of information from
     * the IV and verifies whether the message can be processed or should be
     * considered replayed,
     *
     * @param _iv_data the pointer to the array of bytes containing the IV.
     * @param _instance_id the variable where the instance ID is returned.
     * @param _counter the variable where the counter is returned.
     * @return a value indicating whether the message can be processed (true) or
     * a possible replay attack has been detected (false).
     */
    bool validate_decipher_iv(const byte_t *_iv_data, crypto_instance_t &_instance_id, counter_t &_counter) const;

    /**
     * \brief Updates the data structure storing the information for replay protection.
     *
     * Although the IV is validated by the validate_decipher_iv function, the internal
     * data structure is updated by this method. This two phase process is justified
     * by the need for performing the MAC verification before the update process, to
     * prevent the possibility for DoS attacks.
     *
     * @param _instance_id the instance ID extracted from the IV.
     * @param _counter the counter extracted from the IV.
     */
    void update_decipher_counter(crypto_instance_t _instance_id, counter_t _counter);

protected:
    const EVP_CIPHER_CTX_ptr context_;
    const EVP_CIPHER *const cipher_;

    const secure_vector<byte_t> key_;
    const size_t tag_length_;

    std::array<byte_t, IV_LENGTH> encipher_iv_;
    counter_t encipher_counter_;
    std::map<uint32_t, counter_history_t> decipher_counters;

protected:
    /**
     * \brief Computes the difference between two counter values.
     *
     * @param _lhs the first operand of the subtraction.
     * @param _rhs the second operand of the subtraction.
     * @return the computed difference (the maximum value is returned if the difference is too big).
     */
    friend counter_diff_t operator-(counter_t _lhs, counter_t _rhs);
};

} // namespace vsomeip

#endif //VSOMEIP_OPENSSL_AUTHENTICATED_ENCRYPTION_HPP
