// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include <vsomeip/runtime.hpp>

#include "../../utility/include/utility.hpp"
#include "../../utility/include/byteorder.hpp"
#include "../include/routing_manager_base.hpp"
#include "../../logging/include/logger.hpp"
#include "../../endpoints/include/local_client_endpoint_impl.hpp"
#include "../../endpoints/include/local_server_endpoint_impl.hpp"
#include "../../message/include/serializer.hpp"
#include "../../message/include/deserializer.hpp"

#include "../../crypto/asymmetric/include/rsa_digital_certificate.hpp"
#include "../../crypto/asymmetric/include/rsa_private.hpp"
#include "../../crypto/asymmetric/include/rsa_public.hpp"
#include "../../crypto/random/include/random_impl.hpp"
#include "../../security/include/message_serializer.hpp"
#include "../../security/include/message_deserializer.hpp"
#include "../../security/include/session_establishment.hpp"
#include "../../security/include/session_parameters.hpp"

namespace vsomeip {

routing_manager_base::routing_manager_base(routing_manager_host *_host) :
        host_(_host),
        io_(host_->get_io()),
        client_(host_->get_client()),
        configuration_(host_->get_configuration()),
        digital_certificate_(rsa_digital_certificate::get_certificate(configuration_->get_certificates_path(),
                                                                      configuration_->get_certificate_fingerprint(
                                                                              host_->get_name()),
                                                                      configuration_->get_root_certificate_fingerprint(),
                                                                      rsa_key_length::RSA_2048,
                                                                      digest_algorithm::MD_SHA256)),
        private_key_(std::make_shared<rsa_private>(configuration_->get_private_key_path(host_->get_name()),
                                                   rsa_key_length::RSA_2048, digest_algorithm::MD_SHA256))
#ifdef USE_DLT
        , tc_(tc::trace_connector::get())
#endif
{
    if (!digital_certificate_->is_valid()) {
        VSOMEIP_ERROR << "Failed to load application's certificate";
    }

    if (private_key_->is_valid()) {
        VSOMEIP_INFO << "Loaded private key file: " << configuration_->get_private_key_path(host_->get_name());
    } else {
        VSOMEIP_ERROR << "Failed to load application's private key";
    }
}

routing_manager_base::~routing_manager_base() {
}

boost::asio::io_service & routing_manager_base::get_io() {
    return (io_);
}

client_t routing_manager_base::get_client() const {
    return client_;
}

void routing_manager_base::init() {
}

bool routing_manager_base::offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major,
            minor_version_t _minor) {
    (void)_client;

    crypto_algorithm_packed its_crypto_algorithm;

    // Check whether the application can offer the current service (only if it is the actual offerer)
    if (client_ == _client) {

        if (!digital_certificate_->is_valid()) {
            VSOMEIP_ERROR << "Invalid certificate: impossible to offer service "
                          << std::hex << _service << ":" << _instance;
            return false;
        }

        auto its_security_level = digital_certificate_->minimum_security_level(_service, _instance, true);
        if (security_level::SL_INVALID == its_security_level) {
            VSOMEIP_ERROR << "Application not allowed to offer service "
                          << std::hex << _service << ":" << _instance;
            return false;
        }

        its_crypto_algorithm = configuration_->get_crypto_algorithm(_service, _instance);
        if (!its_crypto_algorithm.is_valid_combination()) {
            its_crypto_algorithm = configuration_->get_default_crypto_algorithm(its_security_level);
        }

        if (its_crypto_algorithm.security_level_ < its_security_level) {
            VSOMEIP_ERROR << "Application allowed to offer service "
                          << std::hex << _service << ":" << _instance
                          << " with minimum security level " << its_security_level
                          << " but requested " << its_crypto_algorithm.security_level_;
            return false;
        }

    }

    // Remote route (incoming only)
    auto its_info = find_service(_service, _instance);
    if (its_info) {
        if (!its_info->is_local()) {
            VSOMEIP_ERROR << "routing_manager_base::offer_service: "
                          << "rejecting service registration. Application: "
                          << std::hex << std::setfill('0') << std::setw(4)
                          << _client << " is trying to offer ["
                          << std::hex << std::setfill('0') << std::setw(4) << _service << "."
                          << std::hex << std::setfill('0') << std::setw(4) << _instance << "."
                          << std::dec << static_cast<std::uint32_t>(_major) << "."
                          << std::dec << _minor << "]"
                          << "] already offered remotely";
            return false;
        } else if (its_info->get_major() == _major
                && its_info->get_minor() == _minor) {
            its_info->set_ttl(DEFAULT_TTL);
        } else {
            host_->on_error(error_code_e::SERVICE_PROPERTY_MISMATCH);
            VSOMEIP_ERROR << "rm_base::offer_service service property mismatch ("
                    << std::hex << std::setw(4) << std::setfill('0') << _client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _instance << ":"
                    << std::dec << static_cast<std::uint32_t>(its_info->get_major()) << ":"
                    << std::dec << its_info->get_minor() << "] passed: "
                    << std::dec << static_cast<std::uint32_t>(_major) << ":"
                    << std::dec << _minor;
            return false;
        }
    } else {
        its_info = create_service_info(_service, _instance, _major, _minor,
                DEFAULT_TTL, true);
    }
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        // Set major version for all registered events of this service and instance
        const auto found_service = events_.find(_service);
        if (found_service != events_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                for (const auto &j : found_instance->second) {
                    j.second->set_version(_major);
                }
            }
        }
    }

    // Setup the session parameters (only if the application is the actual offerer)
    if (client_ == _client) {

        std::lock_guard<std::mutex> its_lock(sessions_mutex_);
        auto its_parameters = find_session_parameters_unlocked(_service, _instance);

        if (!its_parameters) {
            its_parameters = std::make_shared<session_parameters>(its_crypto_algorithm, random_impl::get_instance(),
                                                                  configuration_->get_buffer_shrink_threshold());

            if (its_parameters->is_valid()) {
                sessions_[_service][_instance] = its_parameters;
                VSOMEIP_INFO << "Session parameters setup for service "
                             << std::hex << _service << ":" << _instance
                             << " - security level: " << its_parameters->get_security_level()
                             << " - algorithm: " << its_parameters->get_crypto_algorithm();
            } else {
                VSOMEIP_ERROR << "Session parameters setup FAILED for service "
                              << std::hex << _service << ":" << _instance
                              << " - security level: " << its_parameters->get_security_level();
            }
        }
    }

    return true;
}

void routing_manager_base::stop_offer_service(client_t _client, service_t _service,
            instance_t _instance, major_version_t _major, minor_version_t _minor) {
    (void)_client;
    (void)_major;
    (void)_minor;
    std::map<event_t, std::shared_ptr<event> > events;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        auto its_events_service = events_.find(_service);
        if (its_events_service != events_.end()) {
            auto its_events_instance = its_events_service->second.find(_instance);
            if (its_events_instance != its_events_service->second.end()) {
                for (auto &e : its_events_instance->second)
                    events[e.first] = e.second;

            }
        }
    }
    for (auto &e : events) {
        e.second->unset_message();
        e.second->clear_subscribers();
    }
}

bool routing_manager_base::request_service(client_t _client, service_t _service,
                                           instance_t _instance, major_version_t _major,
                                           minor_version_t _minor, bool _use_exclusive_proxy) {
    (void)_use_exclusive_proxy;

    // Check whether the application can request the current service (only if it is the actual requester)
    if (client_ == _client) {

        if (!digital_certificate_->is_valid()) {
            VSOMEIP_ERROR << "Invalid certificate: impossible to request service "
                          << std::hex << _service << ":" << _instance;
            return false;
        }

        auto its_security_level = digital_certificate_->minimum_security_level(_service, _instance, false);
        if (security_level::SL_INVALID == its_security_level) {
            VSOMEIP_ERROR << "Application not allowed to request service "
                          << std::hex << _service << ":" << _instance;
            return false;
        }
    }

    auto its_info = find_service(_service, _instance);
    if (its_info) {
        if ((_major == its_info->get_major()
                || DEFAULT_MAJOR == its_info->get_major()
                || ANY_MAJOR == _major)
                && (_minor <= its_info->get_minor()
                    || DEFAULT_MINOR == its_info->get_minor()
                    || _minor == ANY_MINOR)) {
            its_info->add_client(_client);
        } else {
            host_->on_error(error_code_e::SERVICE_PROPERTY_MISMATCH);
            VSOMEIP_ERROR << "rm_base::request_service service property mismatch ("
                    << std::hex << std::setw(4) << std::setfill('0') << _client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << _instance << ":"
                    << std::dec << static_cast<std::uint32_t>(its_info->get_major()) << ":"
                    << std::dec << its_info->get_minor() << "] passed: "
                    << std::dec << static_cast<std::uint32_t>(_major) << ":"
                    << std::dec << _minor;
            return false;
        }
    }

    return true;
}

void routing_manager_base::release_service(client_t _client, service_t _service,
            instance_t _instance) {
    auto its_info = find_service(_service, _instance);
    if (its_info) {
        its_info->remove_client(_client);
    }

    // Update the availability for the service
    if (client_ == _client) {

        vsomeip::major_version_t its_major = vsomeip::DEFAULT_MAJOR;
        vsomeip::minor_version_t its_minor = vsomeip::DEFAULT_MINOR;

        if (its_info) {
            if (its_info->is_local()) {
                // The service is offered by the same application
                return;
            }
            its_major = its_info->get_major();
            its_minor = its_info->get_minor();
        } else {
            std::lock_guard<std::mutex> its_lock(local_services_mutex_);
            auto its_service = local_services_.find(_service);
            if (its_service != local_services_.end()) {
                auto its_instance = its_service->second.find(_instance);
                if (its_instance != its_service->second.end()) {
                    its_major = std::get<0>(its_instance->second);
                    its_minor = std::get<1>(its_instance->second);
                }
            }
        }

        on_availability(_service, _instance, false, its_major, its_minor);
    }
}

void routing_manager_base::register_event(client_t _client, service_t _service, instance_t _instance,
            event_t _event, const std::set<eventgroup_t> &_eventgroups, bool _is_field,
            std::chrono::milliseconds _cycle, bool _change_resets_cycle,
            epsilon_change_func_t _epsilon_change_func,
            bool _is_provided, bool _is_shadow, bool _is_cache_placeholder) {
    std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
    bool transfer_subscriptions_from_any_event(false);
    if (its_event) {
        if(!its_event->is_cache_placeholder()) {
            if (its_event->is_field() == _is_field) {
                if (_is_provided) {
                    its_event->set_provided(true);
                }
                if (_is_shadow && _is_provided) {
                    its_event->set_shadow(_is_shadow);
                }
                if (_client == host_->get_client() && _is_provided) {
                    its_event->set_shadow(false);
                }
                for (auto eg : _eventgroups) {
                    its_event->add_eventgroup(eg);
                }
                transfer_subscriptions_from_any_event = true;
            } else {
                VSOMEIP_ERROR << "Event registration update failed. "
                        "Specified arguments do not match existing registration.";
            }
        } else {
            // the found event was a placeholder for caching.
            // update it with the real values
            if(!_is_field) {
                // don't cache payload for non-fields
                its_event->unset_message(true);
            }
            if (_is_shadow && _is_provided) {
                its_event->set_shadow(_is_shadow);
            }
            if (_client == host_->get_client() && _is_provided) {
                its_event->set_shadow(false);
            }
            its_event->set_field(_is_field);
            its_event->set_provided(_is_provided);
            its_event->set_cache_placeholder(false);
            std::shared_ptr<serviceinfo> its_service = find_service(_service, _instance);
            if (its_service) {
                its_event->set_version(its_service->get_major());
            }
            if (_eventgroups.size() == 0) { // No eventgroup specified
                std::set<eventgroup_t> its_eventgroups;
                its_eventgroups.insert(_event);
                its_event->set_eventgroups(its_eventgroups);
            } else {
                for (auto eg : _eventgroups) {
                    its_event->add_eventgroup(eg);
                }
            }

            its_event->set_epsilon_change_function(_epsilon_change_func);
            its_event->set_change_resets_cycle(_change_resets_cycle);
            its_event->set_update_cycle(_cycle);
        }
    } else {
        its_event = std::make_shared<event>(this, _service, _instance, _event, _is_shadow);
        its_event->set_reliable(configuration_->is_event_reliable(_service, _instance, _event));
        its_event->set_field(_is_field);
        its_event->set_provided(_is_provided);
        its_event->set_cache_placeholder(_is_cache_placeholder);
        std::shared_ptr<serviceinfo> its_service = find_service(_service, _instance);
        if (its_service) {
            its_event->set_version(its_service->get_major());
        }

        if (_eventgroups.size() == 0) { // No eventgroup specified
            std::set<eventgroup_t> its_eventgroups;
            its_eventgroups.insert(_event);
            its_event->set_eventgroups(its_eventgroups);
        } else {
            its_event->set_eventgroups(_eventgroups);
        }

        if (_is_shadow && !_epsilon_change_func) {
            std::shared_ptr<vsomeip::cfg::debounce> its_debounce
                = configuration_->get_debounce(_service, _instance, _event);
            if (its_debounce) {
                VSOMEIP_WARNING << "Using debounce configuration for "
                        << " SOME/IP event "
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _service << "."
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _instance << "."
                        << std::hex << std::setw(4) << std::setfill('0')
                        << _event << ".";
                std::stringstream its_debounce_parameters;
                its_debounce_parameters << "(on_change="
                        << (its_debounce->on_change_ ? "true" : "false")
                        << ", ignore=[ ";
                for (auto i : its_debounce->ignore_)
                   its_debounce_parameters << "(" << std::dec << i.first
                           << ", " << std::hex << (int)i.second << ") ";
                its_debounce_parameters << "], interval="
                        << std::dec << its_debounce->interval_ << ")";
                VSOMEIP_WARNING << "Debounce parameters: "
                        << its_debounce_parameters.str();
                _epsilon_change_func = [its_debounce](
                    const std::shared_ptr<payload> &_old,
                    const std::shared_ptr<payload> &_new) {
                    bool is_changed(false), is_elapsed(false);

                    // Check whether we should forward because of changed data
                    if (its_debounce->on_change_) {
                        length_t its_min_length, its_max_length;

                        if (_old->get_length() < _new->get_length()) {
                            its_min_length = _old->get_length();
                            its_max_length = _new->get_length();
                        } else {
                            its_min_length = _new->get_length();
                            its_max_length = _old->get_length();
                        }

                        // Check whether all additional bytes (if any) are excluded
                        for (length_t i = its_min_length; i < its_max_length; i++) {
                            auto j = its_debounce->ignore_.find(i);
                            if (j == its_debounce->ignore_.end() && j->second == 0xFF) {
                                is_changed = true;
                                break;
                            }
                        }

                        if (!is_changed) {
                            const byte_t *its_old = _old->get_data();
                            const byte_t *its_new = _new->get_data();
                            for (length_t i = 0; i < its_min_length; i++) {
                                auto j = its_debounce->ignore_.find(i);
                                if (j == its_debounce->ignore_.end()) {
                                    if (its_old[i] != its_new[i]) {
                                        is_changed = true;
                                        break;
                                    }
                                } else if (j->second != 0xFF) {
                                    if ((its_old[i] & ~(j->second)) != (its_new[i] & ~(j->second))) {
                                        is_changed = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (its_debounce->interval_ > -1) {
                        // Check whether we should forward because of the elapsed time since
                        // we did last time
                        std::chrono::steady_clock::time_point its_current
                            = std::chrono::steady_clock::now();

                        int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           its_current - its_debounce->last_forwarded_).count();
                        is_elapsed = (its_debounce->last_forwarded_ == std::chrono::steady_clock::time_point::max()
                                || elapsed >= its_debounce->interval_);
                        if (is_elapsed || (is_changed && its_debounce->on_change_resets_interval_))
                            its_debounce->last_forwarded_ = its_current;
                    }
                    return (is_changed || is_elapsed);
                };
            } else {
                _epsilon_change_func = [](const std::shared_ptr<payload> &_old,
                                    const std::shared_ptr<payload> &_new) {
                    (void)_old;
                    (void)_new;
                    return true;
                };
            }
        }

        its_event->set_epsilon_change_function(_epsilon_change_func);
        its_event->set_change_resets_cycle(_change_resets_cycle);
        its_event->set_update_cycle(_cycle);

        if (_is_provided) {
            transfer_subscriptions_from_any_event = true;
        }
    }

    if (transfer_subscriptions_from_any_event) {
        // check if someone subscribed to ANY_EVENT and the subscription
        // was stored in the cache placeholder. Move the subscribers
        // into new event
        std::shared_ptr<event> its_any_event =
                find_event(_service, _instance, ANY_EVENT);
        if (its_any_event) {
            std::set<eventgroup_t> any_events_eventgroups =
                    its_any_event->get_eventgroups();
            for (eventgroup_t eventgroup : _eventgroups) {
                auto found_eg = any_events_eventgroups.find(eventgroup);
                if (found_eg != any_events_eventgroups.end()) {
                    std::set<client_t> its_any_event_subscribers =
                            its_any_event->get_subscribers(eventgroup);
                    for (const client_t subscriber : its_any_event_subscribers) {
                        its_event->add_subscriber(eventgroup, subscriber, true);
                    }
                }
            }
        }
    }
    if(!_is_cache_placeholder) {
        its_event->add_ref(_client, _is_provided);
    }

    for (auto eg : _eventgroups) {
        std::shared_ptr<eventgroupinfo> its_eventgroup_info
            = find_eventgroup(_service, _instance, eg);
        if (!its_eventgroup_info) {
            its_eventgroup_info = std::make_shared<eventgroupinfo>();
            std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
            eventgroups_[_service][_instance][eg] = its_eventgroup_info;
        }
        its_eventgroup_info->add_event(its_event);
    }

    std::lock_guard<std::mutex> its_lock(events_mutex_);
    events_[_service][_instance][_event] = its_event;
}

void routing_manager_base::unregister_event(client_t _client, service_t _service, instance_t _instance,
            event_t _event, bool _is_provided) {
    (void)_client;
    std::shared_ptr<event> its_unrefed_event;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        auto found_service = events_.find(_service);
        if (found_service != events_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                auto found_event = found_instance->second.find(_event);
                if (found_event != found_instance->second.end()) {
                    auto its_event = found_event->second;
                    its_event->remove_ref(_client, _is_provided);
                    if (!its_event->has_ref()) {
                        its_unrefed_event = its_event;
                        found_instance->second.erase(found_event);
                    } else if (_is_provided) {
                        its_event->set_provided(false);
                    }
                }
            }
        }
    }
    if (its_unrefed_event) {
        auto its_eventgroups = its_unrefed_event->get_eventgroups();
        for (auto eg : its_eventgroups) {
            std::shared_ptr<eventgroupinfo> its_eventgroup_info
                = find_eventgroup(_service, _instance, eg);
            if (its_eventgroup_info) {
                its_eventgroup_info->remove_event(its_unrefed_event);
                if (0 == its_eventgroup_info->get_events().size()) {
                    remove_eventgroup_info(_service, _instance, eg);
                }
            }
        }
    }
}

std::set<std::shared_ptr<event>> routing_manager_base::find_events(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) const {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    std::set<std::shared_ptr<event> > its_events;
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                return (found_eventgroup->second->get_events());
            }
        }
    }
    return (its_events);
}

void routing_manager_base::subscribe(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            major_version_t _major, event_t _event,
            subscription_type_e _subscription_type) {

    (void) _major;
    (void) _subscription_type;
    std::set<event_t> its_already_subscribed_events;
    bool inserted = insert_subscription(_service, _instance, _eventgroup,
            _event, _client, &its_already_subscribed_events);
    if (inserted) {
        notify_one_current_value(_client, _service, _instance, _eventgroup,
                _event, its_already_subscribed_events);
    }
}

void routing_manager_base::unsubscribe(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event) {
    if (_event != ANY_EVENT) {
        auto its_event = find_event(_service, _instance, _event);
        if (its_event) {
            its_event->remove_subscriber(_eventgroup, _client);
        }
    } else {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            for (auto e : its_eventgroup->get_events()) {
                e->remove_subscriber(_eventgroup, _client);
            }
        }
    }
}

void routing_manager_base::notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force, bool _flush) {
    std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
    if (its_event) {
        auto serializer = get_serializer(_service, _instance, true);
        its_event->set_payload(serializer, _payload, _force, _flush);
    } else {
        VSOMEIP_WARNING << "Attempt to update the undefined event/field ["
            << std::hex << _service << "." << _instance << "." << _event
            << "]";
    }
}

void routing_manager_base::notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force, bool _flush) {
    std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
    if (its_event) {
        // Event is valid for service/instance
        bool found_eventgroup(false);
        bool already_subscribed(false);
        eventgroup_t valid_group = 0;
        // Iterate over all groups of the event to ensure at least
        // one valid eventgroup for service/instance exists.
        for (auto its_group : its_event->get_eventgroups()) {
            auto its_eventgroup = find_eventgroup(_service, _instance, its_group);
            if (its_eventgroup) {
                // Eventgroup is valid for service/instance
                found_eventgroup = true;
                valid_group = its_group;
                if (find_local(_client)) {
                    already_subscribed = its_event->has_subscriber(its_group, _client);
                } else {
                    // Remotes always needs to be marked as subscribed here
                    already_subscribed = true;
                }
                break;
            }
        }
        if (found_eventgroup) {
            if (already_subscribed) {
                auto serializer = get_serializer(_service, _instance, true);
                its_event->set_payload(serializer, _payload, _client, _force, _flush);
            } else {
                std::shared_ptr<message> its_notification
                    = runtime::get()->create_notification();
                its_notification->set_service(_service);
                its_notification->set_instance(_instance);
                its_notification->set_method(_event);
                its_notification->set_payload(_payload);
                auto service_info = find_service(_service, _instance);
                if (service_info) {
                    its_notification->set_interface_version(service_info->get_major());
                }
                {
                    std::lock_guard<std::mutex> its_lock(pending_notify_ones_mutex_);
                    pending_notify_ones_[_service][_instance][valid_group] = its_notification;
                }
            }
        }
    } else {
        VSOMEIP_WARNING << "Attempt to update the undefined event/field ["
            << std::hex << _service << "." << _instance << "." << _event
            << "]";
    }
}

void routing_manager_base::send_pending_notify_ones(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, client_t _client) {
    std::lock_guard<std::mutex> its_lock(pending_notify_ones_mutex_);
    auto its_service = pending_notify_ones_.find(_service);
    if (its_service != pending_notify_ones_.end()) {
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            auto its_group = its_instance->second.find(_eventgroup);
            if (its_group != its_instance->second.end()) {
                notify_one(_service, _instance, its_group->second->get_method(),
                        its_group->second->get_payload(), _client, false, true);
                its_instance->second.erase(_eventgroup);
            }
        }
    }
}

void routing_manager_base::unset_all_eventpayloads(service_t _service,
                                                   instance_t _instance) {
    std::set<std::shared_ptr<event>> its_events;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        const auto found_service = eventgroups_.find(_service);
        if (found_service != eventgroups_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                for (const auto &eventgroupinfo : found_instance->second) {
                    for (const auto &event : eventgroupinfo.second->get_events()) {
                        its_events.insert(event);
                    }
                }
            }
        }
    }
    for (const auto &e : its_events) {
        e->unset_message(true);
    }
}

void routing_manager_base::unset_all_eventpayloads(service_t _service,
                                                   instance_t _instance,
                                                   eventgroup_t _eventgroup) {
    std::set<std::shared_ptr<event>> its_events;
    {
        std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
        const auto found_service = eventgroups_.find(_service);
        if (found_service != eventgroups_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                const auto found_eventgroup = found_instance->second.find(_eventgroup);
                if (found_eventgroup != found_instance->second.end()) {
                    for (const auto &event : found_eventgroup->second->get_events()) {
                        its_events.insert(event);
                    }
                }
            }
        }
    }
    for (const auto &e : its_events) {
        e->unset_message(true);
    }
}

void routing_manager_base::notify_one_current_value(
        client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event,
        const std::set<event_t> &_events_to_exclude) {
    if (_event != ANY_EVENT) {
        std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
        if (its_event && its_event->is_field())
            its_event->notify_one(_client, true);
    } else {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            std::set<std::shared_ptr<event> > its_events = its_eventgroup->get_events();
            for (auto e : its_events) {
                if (e->is_field()
                        && _events_to_exclude.find(e->get_event())
                                == _events_to_exclude.end()) {
                    e->notify_one(_client, true); // TODO: use _flush to send all events together!
                }
            }
        }
    }
}

bool routing_manager_base::send(client_t its_client,
        std::shared_ptr<message> _message,
        bool _flush) {
    bool is_sent(false);
    if (utility::is_request(_message->get_message_type())) {
        _message->set_client(its_client);
    }
    auto serializer = get_serializer(_message->get_service(), _message->get_instance());
    if (serializer) {
        std::vector<byte_t> buffer;
        if (serializer->serialize_message(_message.get(), buffer)) {
            is_sent = send(its_client, buffer.data(), static_cast<uint32_t>(buffer.size()),
                           _message->get_instance(),
                           _flush, _message->is_reliable());
        } else {
            VSOMEIP_ERROR << "Failed to serialize message. Check message size!";
        }
    }
    return (is_sent);
}

// ********************************* PROTECTED **************************************
std::shared_ptr<serviceinfo> routing_manager_base::create_service_info(
        service_t _service, instance_t _instance, major_version_t _major,
        minor_version_t _minor, ttl_t _ttl, bool _is_local_service) {
    std::shared_ptr<serviceinfo> its_info =
            std::make_shared<serviceinfo>(_major, _minor, _ttl, _is_local_service);

    {
        std::lock_guard<std::mutex> its_lock(services_mutex_);
        services_[_service][_instance] = its_info;
    }
    if (!_is_local_service) {
        std::lock_guard<std::mutex> its_lock(services_remote_mutex_);
        services_remote_[_service][_instance] = its_info;
    }
    return its_info;
}

std::shared_ptr<serviceinfo> routing_manager_base::find_service(
        service_t _service, instance_t _instance) const {
    std::shared_ptr<serviceinfo> its_info;
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    auto found_service = services_.find(_service);
    if (found_service != services_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            its_info = found_instance->second;
        }
    }
    return (its_info);
}

void routing_manager_base::clear_service_info(service_t _service, instance_t _instance,
        bool _reliable) {
    std::shared_ptr<serviceinfo> its_info(find_service(_service, _instance));
    if (!its_info) {
        return;
    }

    bool deleted_instance(false);
    bool deleted_service(false);
    {
        std::lock_guard<std::mutex> its_lock(services_mutex_);

        // Clear service_info and service_group
        std::shared_ptr<endpoint> its_empty_endpoint;
        if (!its_info->get_endpoint(!_reliable)) {

            clear_session_parameters(_service, _instance);

            if (1 >= services_[_service].size()) {
                services_.erase(_service);
                deleted_service = true;
            } else {
                services_[_service].erase(_instance);
                deleted_instance = true;
            }
        } else {
            its_info->set_endpoint(its_empty_endpoint, _reliable);
        }
    }

    if ((deleted_instance || deleted_service) && !its_info->is_local()) {
        std::lock_guard<std::mutex> its_lock(services_remote_mutex_);
        if (deleted_service) {
            services_remote_.erase(_service);
        } else if (deleted_instance) {
            services_remote_[_service].erase(_instance);
        }
    }
}

services_t routing_manager_base::get_services() const {
    std::lock_guard<std::mutex> its_lock(services_mutex_);
    return services_;
}

bool routing_manager_base::is_available(service_t _service, instance_t _instance,
        major_version_t _major) {
    bool available(false);
    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
    auto its_service = local_services_.find(_service);
    if (its_service != local_services_.end()) {
        if (_instance == ANY_INSTANCE) {
            return true;
        }
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            if (_major == ANY_MAJOR) {
                return true;
            }
            if (std::get<0>(its_instance->second) == _major) {
                available = true;
            }
        }
    }
    return available;
}

client_t routing_manager_base::find_local_client(service_t _service, instance_t _instance) {
    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
    client_t its_client(VSOMEIP_ROUTING_CLIENT);
    auto its_service = local_services_.find(_service);
    if (its_service != local_services_.end()) {
        auto its_instance = its_service->second.find(_instance);
        if (its_instance != its_service->second.end()) {
            its_client = std::get<2>(its_instance->second);
        }
    }
    return its_client;
}

std::shared_ptr<endpoint> routing_manager_base::create_local_unlocked(client_t _client) {
    std::stringstream its_path;
    its_path << utility::get_base_path(configuration_) << std::hex << _client;

#ifdef _WIN32
    boost::asio::ip::address address = boost::asio::ip::address::from_string("127.0.0.1");
    int port = VSOMEIP_INTERNAL_BASE_PORT + _client;
    VSOMEIP_INFO << "Connecting to ["
        << std::hex << _client << "] at " << port;
#else
    VSOMEIP_INFO << "Client [" << std::hex << get_client() << "] is connecting to ["
            << std::hex << _client << "] at " << its_path.str();
#endif
    std::shared_ptr<local_client_endpoint_impl> its_endpoint = std::make_shared<
        local_client_endpoint_impl>(shared_from_this(),
#ifdef _WIN32
        boost::asio::ip::tcp::endpoint(address, port)
#else
        boost::asio::local::stream_protocol::endpoint(its_path.str())
#endif
    , io_, configuration_->get_max_message_size_local(),
    configuration_->get_endpoint_queue_limit_local());

    // Messages sent to the VSOMEIP_ROUTING_CLIENT are meant to be routed to
    // external devices. Therefore, its local endpoint must not be found by
    // a call to find_local. Thus it must not be inserted to the list of local
    // clients.
    if (_client != VSOMEIP_ROUTING_CLIENT) {
        local_endpoints_[_client] = its_endpoint;
    }
    register_client_error_handler(_client, its_endpoint);

    return its_endpoint;
}

std::shared_ptr<endpoint> routing_manager_base::create_local(client_t _client) {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return create_local_unlocked(_client);
}

std::shared_ptr<endpoint> routing_manager_base::find_local_unlocked(client_t _client) {
    std::shared_ptr<endpoint> its_endpoint;
    auto found_endpoint = local_endpoints_.find(_client);
    if (found_endpoint != local_endpoints_.end()) {
        its_endpoint = found_endpoint->second;
    }
    return (its_endpoint);
}

std::shared_ptr<endpoint> routing_manager_base::find_local(client_t _client) {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return find_local_unlocked(_client);
}

std::shared_ptr<endpoint> routing_manager_base::find_or_create_local(client_t _client) {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    std::shared_ptr<endpoint> its_endpoint(find_local_unlocked(_client));
    if (!its_endpoint) {
        its_endpoint = create_local_unlocked(_client);
        its_endpoint->start();
    }
    return (its_endpoint);
}

void routing_manager_base::remove_local(client_t _client) {
    remove_local(_client, get_subscriptions(_client));
}

void routing_manager_base::remove_local(client_t _client,
                  const std::set<std::tuple<service_t, instance_t, eventgroup_t>>& _subscribed_eventgroups) {
    for (auto its_subscription : _subscribed_eventgroups) {
        host_->on_subscription(std::get<0>(its_subscription), std::get<1>(its_subscription),
                std::get<2>(its_subscription), _client, false, [](const bool _subscription_accepted){ (void)_subscription_accepted; });
        routing_manager_base::unsubscribe(_client, std::get<0>(its_subscription),
                std::get<1>(its_subscription), std::get<2>(its_subscription), ANY_EVENT);
    }
    std::shared_ptr<endpoint> its_endpoint(find_local(_client));
    if (its_endpoint) {
        its_endpoint->register_error_handler(nullptr);
        its_endpoint->stop();
        VSOMEIP_INFO << "Client [" << std::hex << get_client() << "] is closing connection to ["
                      << std::hex << _client << "]";
        std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
        local_endpoints_.erase(_client);
    }
    {
        std::lock_guard<std::mutex> its_lock(local_services_mutex_);
        // Finally remove all services that are implemented by the client.
        std::set<std::pair<service_t, instance_t>> its_services;
        for (auto& s : local_services_) {
            for (auto& i : s.second) {
                if (std::get<2>(i.second) == _client) {
                    its_services.insert({ s.first, i.first });
                    on_availability(s.first, i.first, false, std::get<0>(i.second), std::get<1>(i.second));
                }
            }
        }

        for (auto& si : its_services) {
            local_services_[si.first].erase(si.second);
            if (local_services_[si.first].size() == 0)
                local_services_.erase(si.first);
        }
    }
}

std::shared_ptr<endpoint> routing_manager_base::find_local(service_t _service,
        instance_t _instance) {
    return find_local(find_local_client(_service, _instance));
}

std::unordered_set<client_t> routing_manager_base::get_connected_clients() {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    std::unordered_set<client_t> clients;
    for (auto its_client : local_endpoints_) {
        clients.insert(its_client.first);
    }
    return clients;
}

std::shared_ptr<event> routing_manager_base::find_event(service_t _service,
        instance_t _instance, event_t _event) const {
    std::shared_ptr<event> its_event;
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    auto find_service = events_.find(_service);
    if (find_service != events_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            auto find_event = find_instance->second.find(_event);
            if (find_event != find_instance->second.end()) {
                its_event = find_event->second;
            }
        }
    }
    return (its_event);
}

std::shared_ptr<eventgroupinfo> routing_manager_base::find_eventgroup(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup) const {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);

    std::shared_ptr<eventgroupinfo> its_info(nullptr);
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                its_info = found_eventgroup->second;
                std::shared_ptr<serviceinfo> its_service_info
                    = find_service(_service, _instance);
                if (its_service_info) {
                    std::string its_multicast_address;
                    uint16_t its_multicast_port;
                    if (configuration_->get_multicast(_service, _instance,
                            _eventgroup,
                            its_multicast_address, its_multicast_port)) {
                        try {
                            its_info->set_multicast(
                                    boost::asio::ip::address::from_string(
                                            its_multicast_address),
                                    its_multicast_port);
                        }
                        catch (...) {
                            VSOMEIP_ERROR << "Eventgroup ["
                                << std::hex << std::setw(4) << std::setfill('0')
                                << _service << "." << _instance << "." << _eventgroup
                                << "] is configured as multicast, but no valid "
                                       "multicast address is configured!";
                        }
                    }
                    its_info->set_major(its_service_info->get_major());
                    its_info->set_ttl(its_service_info->get_ttl());
                    its_info->set_threshold(configuration_->get_threshold(
                            _service, _instance, _eventgroup));
                }
            }
        }
    }
    return (its_info);
}

void routing_manager_base::remove_eventgroup_info(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup) {
    std::lock_guard<std::mutex> its_lock(eventgroups_mutex_);
    auto found_service = eventgroups_.find(_service);
    if (found_service != eventgroups_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            found_instance->second.erase(_eventgroup);
        }
    }
}

bool routing_manager_base::send_local_notification(client_t _client,
        const byte_t *_data, uint32_t _size, instance_t _instance,
        bool _flush, bool _reliable, bool _is_valid_crc) {
#ifdef USE_DLT
    bool has_local(false);
#endif
    bool has_remote(false);
    method_t its_method = VSOMEIP_BYTES_TO_WORD(_data[VSOMEIP_METHOD_POS_MIN],
            _data[VSOMEIP_METHOD_POS_MAX]);
    service_t its_service = VSOMEIP_BYTES_TO_WORD(
            _data[VSOMEIP_SERVICE_POS_MIN], _data[VSOMEIP_SERVICE_POS_MAX]);
    std::shared_ptr<event> its_event = find_event(its_service, _instance, its_method);
    if (its_event && !its_event->is_shadow()) {
        std::vector< byte_t > its_data;

        for (auto its_client : its_event->get_subscribers()) {
            // local
            if (its_client == VSOMEIP_ROUTING_CLIENT) {
                has_remote = true;
                continue;
            }
#ifdef USE_DLT
            else {
                has_local = true;
            }
#endif
            std::shared_ptr<endpoint> its_local_target = find_local(its_client);
            if (its_local_target) {
                send_local(its_local_target, _client, _data, _size,
                           _instance, _flush, _reliable, VSOMEIP_SEND, _is_valid_crc);
            }
        }
    }
#ifdef USE_DLT
    // Trace the message if a local client but will _not_ be forwarded to the routing manager
    if (has_local && !has_remote) {
        const uint16_t its_data_size
            = uint16_t(_size > USHRT_MAX ? USHRT_MAX : _size);

        tc::trace_header its_header;
        if (its_header.prepare(nullptr, true, _instance))
            tc_->trace(its_header.data_, VSOMEIP_TRACE_HEADER_SIZE,
                    _data, its_data_size);
    }
#endif
    return has_remote;
}

bool routing_manager_base::send_local(
        std::shared_ptr<endpoint>& _target, client_t _client,
        const byte_t *_data, uint32_t _size, instance_t _instance,
        bool _flush, bool _reliable, uint8_t _command, bool _is_valid_crc) const {
    const std::size_t its_complete_size = VSOMEIP_SEND_COMMAND_SIZE
            - VSOMEIP_COMMAND_HEADER_SIZE + _size;
    const client_t sender = get_client();

    std::vector<byte_t> its_command_header(VSOMEIP_SEND_COMMAND_SIZE);
    its_command_header[VSOMEIP_COMMAND_TYPE_POS] = _command;
    std::memcpy(&its_command_header[VSOMEIP_COMMAND_CLIENT_POS],
            &sender, sizeof(client_t));
    std::memcpy(&its_command_header[VSOMEIP_COMMAND_SIZE_POS_MIN],
            &its_complete_size, sizeof(_size));
    std::memcpy(&its_command_header[VSOMEIP_SEND_COMMAND_INSTANCE_POS_MIN],
            &_instance, sizeof(instance_t));
    std::memcpy(&its_command_header[VSOMEIP_SEND_COMMAND_FLUSH_POS],
            &_flush, sizeof(bool));
    std::memcpy(&its_command_header[VSOMEIP_SEND_COMMAND_RELIABLE_POS],
            &_reliable, sizeof(bool));
    std::memcpy(&its_command_header[VSOMEIP_SEND_COMMAND_VALID_CRC_POS],
            &_is_valid_crc, sizeof(bool));
    // Add target client, only relevant for selective notifications
    std::memcpy(&its_command_header[VSOMEIP_SEND_COMMAND_DST_CLIENT_POS_MIN],
            &_client, sizeof(client_t));

    return _target->send(its_command_header, _data, _size);
}

bool routing_manager_base::insert_subscription(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _event, client_t _client, std::set<event_t> *_already_subscribed_events) {
    bool is_inserted(false);
    if (_event != ANY_EVENT) { // subscribe to specific event
        std::shared_ptr<event> its_event = find_event(_service, _instance, _event);
        if (its_event) {
            is_inserted = its_event->add_subscriber(_eventgroup, _client,
                    host_->is_routing());
        } else {
            VSOMEIP_WARNING << "routing_manager_base::insert_subscription("
                << std::hex << std::setw(4) << std::setfill('0') << _client << "): ["
                << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                << std::hex << std::setw(4) << std::setfill('0') << _instance << "."
                << std::hex << std::setw(4) << std::setfill('0') << _eventgroup << "."
                << std::hex << std::setw(4) << std::setfill('0') << _event << "]"
                << " received subscription for unknown (unrequested / "
                << "unoffered) event. Creating placeholder event holding "
                << "subscription until event is requested/offered.";
            is_inserted = create_placeholder_event_and_subscribe(_service,
                    _instance, _eventgroup, _event, _client);
        }
    } else { // subscribe to all events of the eventgroup
        std::shared_ptr<eventgroupinfo> its_eventgroup
            = find_eventgroup(_service, _instance, _eventgroup);
        bool create_place_holder(false);
        if (its_eventgroup) {
            std::set<std::shared_ptr<event>> its_events = its_eventgroup->get_events();
            if (!its_events.size()) {
                create_place_holder = true;
            } else {
                for (const auto &e : its_events) {
                    if (e->is_subscribed(_client)) {
                        // client is already subscribed to event from eventgroup
                        // this can happen if events are members of multiple
                        // eventgroups
                        _already_subscribed_events->insert(e->get_event());
                    }
                    is_inserted = e->add_subscriber(_eventgroup, _client,
                            host_->is_routing()) || is_inserted;
                }
            }
        } else {
            create_place_holder = true;
        }
        if (create_place_holder) {
            VSOMEIP_WARNING << "routing_manager_base::insert_subscription("
                << std::hex << std::setw(4) << std::setfill('0') << _client << "): ["
                << std::hex << std::setw(4) << std::setfill('0') << _service << "."
                << std::hex << std::setw(4) << std::setfill('0') << _instance << "."
                << std::hex << std::setw(4) << std::setfill('0') << _eventgroup << "."
                << std::hex << std::setw(4) << std::setfill('0') << _event << "]"
                << " received subscription for unknown (unrequested / "
                << "unoffered) eventgroup. Creating placeholder event holding "
                << "subscription until event is requested/offered.";
            is_inserted = create_placeholder_event_and_subscribe(_service,
                    _instance, _eventgroup, _event, _client);
        }
    }
    return is_inserted;
}

#ifndef _WIN32
bool routing_manager_base::check_credentials(client_t _client, uid_t _uid, gid_t _gid) {
    return configuration_->check_credentials(_client, _uid, _gid);
}
#endif

void routing_manager_base::send_pending_subscriptions(service_t _service,
        instance_t _instance, major_version_t _major) {
    for (auto &ps : pending_subscriptions_) {
        if (ps.service_ == _service &&
                ps.instance_ == _instance && ps.major_ == _major) {
            send_subscribe(client_, ps.service_, ps.instance_,
                    ps.eventgroup_, ps.major_, ps.event_, ps.subscription_type_);
        }
    }
}

void routing_manager_base::remove_pending_subscription(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, event_t _event) {
    if (_eventgroup == 0xFFFF) {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance) {
                it = pending_subscriptions_.erase(it);
            } else {
                it++;
            }
        }
    } else if (_event == ANY_EVENT) {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance
                    && it->eventgroup_ == _eventgroup) {
                it = pending_subscriptions_.erase(it);
            } else {
                it++;
            }
        }
    } else {
        for (auto it = pending_subscriptions_.begin();
                it != pending_subscriptions_.end();) {
            if (it->service_ == _service
                    && it->instance_ == _instance
                    && it->eventgroup_ == _eventgroup
                    && it->event_ == _event) {
                it = pending_subscriptions_.erase(it);
                break;
            } else {
                it++;
            }
        }
    }
}

std::set<std::tuple<service_t, instance_t, eventgroup_t>>
routing_manager_base::get_subscriptions(const client_t _client) {
    std::set<std::tuple<service_t, instance_t, eventgroup_t>> result;
    std::lock_guard<std::mutex> its_lock(events_mutex_);
    for (auto its_service : events_) {
        for (auto its_instance : its_service.second) {
            for (auto its_event : its_instance.second) {
                auto its_eventgroups = its_event.second->get_eventgroups(_client);
                for (auto e : its_eventgroups) {
                    result.insert(std::make_tuple(
                                    its_service.first,
                                    its_instance.first,
                                    e));
                }
            }
        }
    }
    return result;
}

void routing_manager_base::send_identify_request(service_t _service,
        instance_t _instance, major_version_t _major, bool _reliable) {
    auto message = runtime::get()->create_message(_reliable);
    message->set_service(_service);
    message->set_instance(_instance);
    message->set_client(get_client());
    message->set_method(ANY_METHOD - 1);
    message->set_interface_version(_major);
    message->set_message_type(message_type_e::MT_REQUEST);

    // Initiate a request/response to the remote service
    // Use host for sending to ensure correct session id is set
    host_->send(message, true);
}

std::map<client_t, std::shared_ptr<endpoint>>
routing_manager_base::get_local_endpoints() {
    std::lock_guard<std::mutex> its_lock(local_endpoint_mutex_);
    return local_endpoints_;
}

void routing_manager_base::send_pending_events(service_t _service, instance_t _instance) {

    auto serializer = get_serializer(_service, _instance);
    if (!serializer) {
        return;
    }

    std::vector<std::shared_ptr<event>> its_events;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        const auto found_service = events_.find(_service);
        if (found_service == events_.end()) {
            return;
        }
        const auto found_instance = found_service->second.find(_instance);
        if (found_instance == found_service->second.end()) {
            return;
        }

        // Get a copy of the events to release the lock
        its_events.reserve(found_instance->second.size());
        for (const auto& pair : found_instance->second) {
            its_events.emplace_back(pair.second);
        }
    }

    // Send the initial notification if necessary
    std::for_each(its_events.begin(), its_events.end(), [&serializer](const std::shared_ptr<event>& _event) {
        auto payload = _event->get_cached_payload();
        if (payload) {
            _event->set_payload(serializer, payload, true, false);
        }
    });
}

std::shared_ptr<session_parameters>
routing_manager_base::find_session_parameters(service_t _service, instance_t _instance) const {

    std::lock_guard<std::mutex> its_lock(sessions_mutex_);
    return find_session_parameters_unlocked(_service, _instance);
}

std::shared_ptr<session_parameters>
routing_manager_base::find_session_parameters_unlocked(service_t _service, instance_t _instance) const {

    std::shared_ptr<session_parameters> its_info;

    auto found_service = sessions_.find(_service);
    if (found_service != sessions_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            its_info = found_instance->second;
        }
    }

    return (its_info);
}

bool routing_manager_base::is_session_established(service_t _service, instance_t _instance) {
    return static_cast<bool>(find_session_parameters(_service, _instance));
}

void routing_manager_base::set_session_parameters(service_t _service, instance_t _instance,
                                                  std::shared_ptr<session_parameters> _session_parameters) {

    std::lock_guard<std::mutex> its_lock(sessions_mutex_);
    sessions_[_service][_instance] = std::move(_session_parameters);
}

void routing_manager_base::clear_session_parameters(service_t _service, instance_t _instance,
                                                    bool _remove_pending_requests) {

    if (_remove_pending_requests) {
        remove_pending_request(_service, _instance);
    }

    {
        std::lock_guard<std::mutex> its_lock(sessions_mutex_);
        if (0 != sessions_[_service].erase(_instance)) {
            if (sessions_[_service].empty()) {
                sessions_.erase(_service);
            }
            VSOMEIP_INFO << "Session parameters reset for service " << std::hex << _service << ":" << _instance;
        }
    }
}

std::shared_ptr<message_serializer> routing_manager_base::get_serializer(service_t _service, instance_t _instance,
                                                                         bool _silent) const {
    auto session_info = find_session_parameters(_service, _instance);
    auto serializer = session_info
                      ? session_info->get_serializer()
                      : std::shared_ptr<message_serializer>();

    if (!serializer && !_silent) {
        VSOMEIP_WARNING << "Message serializer not yet initialized ["
                        << std::hex << _service << "." << _instance << "]";
    }

    return serializer;
}

std::shared_ptr<message_deserializer> routing_manager_base::get_deserializer(service_t _service, instance_t _instance,
                                                                             bool _silent) const {
    auto session_info = find_session_parameters(_service, _instance);
    auto deserializer = session_info
                        ? session_info->get_deserializer()
                        : std::shared_ptr<message_deserializer>();

    if (!deserializer && !_silent) {
        VSOMEIP_WARNING << "Message deserializer not yet initialized ["
                        << std::hex << _service << "." << _instance << "]";
    }

    return deserializer;
}

bool routing_manager_base::send_session_establishment_request(service_t _service, instance_t _instance,
                                                              major_version_t _major, minor_version_t _minor,
                                                              bool _allow_self_request) {

    std::shared_ptr<pending_session_establishment_request_t> pending_request;
    {
        std::lock_guard<std::mutex> its_lock(pending_session_establishment_requests_mutex_);
        pending_request = find_pending_request_unlocked(_service, _instance);
        if (pending_request) {
            // Session establishment request already sent
            return true;
        }

        auto its_session = find_session_parameters(_service, _instance);
        if (its_session) {
            if (_allow_self_request && its_session->is_valid() && its_session->is_provider()) {
                // The service is offered by the same application
                on_availability(_service, _instance, true, _major, _minor);
                return true;
            } else {
                clear_session_parameters(_service, _instance, false);
            }
        }

        pending_request = std::make_shared<pending_session_establishment_request_t>(_major, _minor, host_->get_io());
        pending_session_establishment_requests_[_service][_instance] = pending_request;
    }
    return send_session_establishment_request_unlocked(_service, _instance, pending_request);
}

void routing_manager_base::send_session_establishment_request_timeout(service_t _service, instance_t _instance,
                                                                      const boost::system::error_code &_error) {

    if (_error == boost::asio::error::operation_aborted) {
        return;
    }

    auto pending_request = find_pending_request(_service, _instance);
    if (!pending_request) {
        VSOMEIP_WARNING << "Pending session establishment request timer expired but no pending request found: "
                        << std::hex << _service << ":" << _instance;
        return;
    }

    if (pending_request->challenges_.size() >= configuration_->get_session_establishment_max_repetitions()) {
        VSOMEIP_ERROR << "No session establishment response received: " << std::hex << _service << ":" << _instance;
        on_availability(_service, _instance, false, pending_request->major_version_, pending_request->minor_version_);
        return;
    }

    send_session_establishment_request_unlocked(_service, _instance, pending_request);
}

bool routing_manager_base::send_session_establishment_request_unlocked(
        service_t _service, instance_t _instance,
        std::shared_ptr<pending_session_establishment_request_t> &_pending_request) {

    if (!_pending_request) {
        return false;
    }

    // If necessary, the endpoint selection is switched before sending the actual message
    const bool reliable = false;
    session_establishment_request request(_service, _instance, client_, _pending_request->major_version_,
                                          reliable, asymmetric_crypto_algorithm::CA_RSA2048_SHA256,
                                          digital_certificate_->get_fingerprint(),
                                          random_impl::get_instance());

    if (!request.is_valid()) {
        VSOMEIP_ERROR << "Failed to create the session establishment request for service "
                      << std::hex << _service << ":" << _instance;
        return false;
    }

    serializer its_serializer(configuration_->get_buffer_shrink_threshold());
    request.set_session(host_->get_session());
    if (!its_serializer.serialize(&request)) {
        VSOMEIP_ERROR << "Failed to serialize the session establishment request for service "
                      << std::hex << _service << ":" << _instance;
        return false;
    }

    {
        std::lock_guard<std::mutex> its_lock(_pending_request->mutex_);
        if (_pending_request->establishment_completed_) {
            return true;
        }

        const auto delay = configuration_->get_session_establishment_repetitions_delay();
        const auto ratio = configuration_->get_session_establishment_repetitions_delay_ratio();
        const auto tries = _pending_request->challenges_.size();
        const auto timer_timeout = std::chrono::milliseconds(static_cast<int>(delay * std::pow(ratio, tries)));
        _pending_request->add_challenge(request.get_challenge());
        _pending_request->request_timer_.expires_from_now(timer_timeout);
        _pending_request->request_timer_.async_wait(std::bind(
                &routing_manager_base::send_session_establishment_request_timeout,
                shared_from_this(), _service, _instance, std::placeholders::_1));
    }

    if (!send(client_, its_serializer.get_data(), its_serializer.get_size(), _instance, true, reliable)) {
        VSOMEIP_ERROR << "Failed to send the session establishment request for service "
                      << std::hex << _service << ":" << _instance;
        return false;
    }

    VSOMEIP_INFO << "Session establishment request sent for service " << std::hex << _service << ":" << _instance;
    return true;
}

bool routing_manager_base::dispatch_session_establishment_message(service_t _service, instance_t _instance,
                                                                  method_t _method, bool _reliable,
                                                                  const byte_t *_data, length_t _size) {

    if (session_establishment_message::METHOD_ID != _method || _size <= VSOMEIP_PAYLOAD_POS) {
        return false;
    }

    auto session_info = find_session_parameters(_service, _instance);
    auto type = static_cast<message_type_e>(_data[VSOMEIP_MESSAGE_TYPE_POS]);

    switch (type) {

        case message_type_e::MT_REQUEST: {
            if (session_info && session_info->is_valid() && session_info->is_provider()) {
                on_session_establishment_request_received(session_info, _data, _size, _instance, _reliable);
            } else {
                VSOMEIP_WARNING << "Received a session establishment request for a service not provided: "
                                << std::hex << _service << ":" << _instance;
            }
            return true;
        }

        case message_type_e::MT_RESPONSE: {

            if (!session_info) {
                major_version_t major;
                minor_version_t minor;
                if (on_session_establishment_response_received(_data, _size, _instance, major, minor)) {
                    on_availability(_service, _instance, true, major, minor);
                }
            } else {
                VSOMEIP_WARNING << "Received a session establishment response but the session has already been established: "
                                << std::hex << _service << ":" << _instance;
            }

            return true;
        }

        default:
            return true;
    }
}

bool routing_manager_base::on_session_establishment_request_received(
        const std::shared_ptr<session_parameters> &_session_parameters,
        const byte_t *_data, length_t _size,
        instance_t _instance, bool _reliable) {

    session_establishment_request request;
    deserializer its_deserializer(configuration_->get_buffer_shrink_threshold());
    its_deserializer.set_data(_data, _size);
    if (!request.deserialize(&its_deserializer) || return_code_e::E_OK != request.get_return_code()) {
        VSOMEIP_WARNING << "Failed to deserialize a session establishment request";
        return false;
    }
    request.set_instance(_instance);
    request.set_reliable(_reliable);

    if (asymmetric_crypto_algorithm::CA_RSA2048_SHA256 != request.get_asymmetric_algorithm()) {
        VSOMEIP_WARNING << "Session establishment request with unknown asymmetric crypto algorithm";
        return false;
    }

    auto peer_certificate = rsa_digital_certificate::get_certificate(configuration_->get_certificates_path(),
                                                                     request.get_fingerprint(),
                                                                     configuration_->get_root_certificate_fingerprint(),
                                                                     rsa_key_length::RSA_2048,
                                                                     digest_algorithm::MD_SHA256);

    if (!is_peer_allowed(peer_certificate, request.get_service(), request.get_instance(),
                         _session_parameters->get_security_level(), false)) {
        return false;
    };

    session_establishment_response response(request, digital_certificate_->get_fingerprint(), _session_parameters,
                                            private_key_, peer_certificate->get_public_key());
    if (!response.is_valid()) {
        VSOMEIP_ERROR << "Failed to create the session establishment response for service "
                      << std::hex << request.get_service() << ":" << response.get_instance();
        return false;
    }

    serializer its_serializer(configuration_->get_buffer_shrink_threshold());
    if (!its_serializer.serialize(&response)) {
        VSOMEIP_ERROR << "Failed to serialize the session establishment response for service "
                      << std::hex << request.get_service() << ":" << response.get_instance();
        return false;
    }

    if (!send(client_, its_serializer.get_data(), its_serializer.get_size(), response.get_instance(), true,
              response.is_reliable())) {
        VSOMEIP_ERROR << "Failed to send the session establishment request for service "
                      << std::hex << request.get_service() << ":" << response.get_instance();
        return false;
    }

    VSOMEIP_INFO << "Session establishment response sent for service "
                 << std::hex << response.get_service() << ":" << response.get_instance();
    return true;
}

bool routing_manager_base::on_session_establishment_response_received(const byte_t *_data, length_t _size,
                                                                      instance_t _instance,
                                                                      major_version_t &_major,
                                                                      minor_version_t &_minor) {

    session_establishment_response response(configuration_->get_buffer_shrink_threshold());
    deserializer its_deserializer(configuration_->get_buffer_shrink_threshold());
    its_deserializer.set_data(_data, _size);
    if (!response.deserialize_base(&its_deserializer) || return_code_e::E_OK != response.get_return_code()) {
        VSOMEIP_WARNING << "Failed to deserialize a session establishment response";
        return false;
    }

    if (asymmetric_crypto_algorithm::CA_RSA2048_SHA256 != response.get_asymmetric_algorithm()) {
        VSOMEIP_WARNING << "Session establishment response with unknown asymmetric crypto algorithm";
        return false;
    }

    auto service = response.get_service();
    response.set_instance(_instance);

    {
        auto pending_request = find_pending_request(service, _instance);
        if (!pending_request) {
            VSOMEIP_WARNING << "Received a session establishment response not corresponding to a previous request: "
                            << std::hex << service << ":" << _instance;
            return false;
        }

        std::unique_lock<std::mutex> its_lock(pending_request->mutex_);
        if (pending_request->establishment_completed_) {
            return false;
        }

        if (!pending_request->is_valid_challenge(response.get_challenge())) {
            VSOMEIP_WARNING << "Received a session establishment response not corresponding to a previous request: "
                            << std::hex << service << ":" << _instance;
            return false;
        }
        _major = pending_request->major_version_;
        _minor = pending_request->minor_version_;

        auto peer_certificate = rsa_digital_certificate::get_certificate(configuration_->get_certificates_path(),
                                                                         response.get_fingerprint(),
                                                                         configuration_->get_root_certificate_fingerprint(),
                                                                         rsa_key_length::RSA_2048,
                                                                         digest_algorithm::MD_SHA256);

        auto its_security_level = digital_certificate_->minimum_security_level(
                response.get_service(), response.get_instance(), false);

        if (security_level::SL_INVALID == its_security_level || response.get_security_level() < its_security_level) {
            VSOMEIP_ERROR << "Application allowed to request service "
                          << std::hex << response.get_service() << ":" << response.get_instance()
                          << " with minimum security level " << its_security_level
                          << " but found " << response.get_security_level();
            return false;
        }

        if (!is_peer_allowed(peer_certificate, response.get_service(), response.get_instance(),
                             response.get_security_level(), true)) {
            return false;
        };

        response.set_crypto_material(private_key_, peer_certificate->get_public_key());
        if (!response.deserialize(&its_deserializer)) {
            VSOMEIP_WARNING << "Failed to deserialize a session establishment response";
            return false;
        }
    }

    remove_pending_request(service, _instance);

    set_session_parameters(response.get_service(), response.get_instance(), response.get_session_parameters());
    VSOMEIP_INFO << "Session establishment completed correctly "
                 << std::hex << response.get_service() << ":" << response.get_instance();

    return true;
}

std::shared_ptr<pending_session_establishment_request_t>
routing_manager_base::find_pending_request(service_t _service, instance_t _instance) {
    std::lock_guard<std::mutex> its_lock(pending_session_establishment_requests_mutex_);
    return find_pending_request_unlocked(_service, _instance);
}

std::shared_ptr<pending_session_establishment_request_t>
routing_manager_base::find_pending_request_unlocked(service_t _service, instance_t _instance) {

    std::shared_ptr<pending_session_establishment_request_t> pending_request;

    auto found_service = pending_session_establishment_requests_.find(_service);
    if (found_service != pending_session_establishment_requests_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            pending_request = found_instance->second;
        }
    }

    return (pending_request);
}

void routing_manager_base::remove_pending_request(service_t _service, instance_t _instance) {

    std::lock_guard<std::mutex> its_lock(pending_session_establishment_requests_mutex_);
    auto found_service = find_pending_request_unlocked(_service, _instance);
    if (found_service) {

        {
            std::lock_guard<std::mutex> its_lock_request(found_service->mutex_);
            found_service->establishment_completed_ = true;
            found_service->request_timer_.cancel();
        }

        pending_session_establishment_requests_[_service].erase(_instance);
        if (pending_session_establishment_requests_[_service].empty()) {
            pending_session_establishment_requests_.erase(_service);
        }
    }
}

bool routing_manager_base::is_peer_allowed(const std::shared_ptr<digital_certificate> &_digital_certificate,
                                           service_t _service, instance_t _instance, security_level _security_level,
                                           bool provider) {

    std::string role = provider ? "offer" : "request";

    if (!_digital_certificate->is_valid()) {
        VSOMEIP_ERROR << "Invalid certificate: peer not allowed to " << role << " service "
                      << std::hex << _service << ":" << _instance;
        return false;
    }

    security_level its_security_level = _digital_certificate->minimum_security_level(_service, _instance, provider);
    if (security_level::SL_INVALID == its_security_level) {
        VSOMEIP_ERROR << "Peer not allowed to " << role << " service "
                      << std::hex << _service << ":" << _instance;
        return false;
    }

    if (_security_level < its_security_level) {
        VSOMEIP_ERROR << "Peer allowed to " << role << " service "
                      << std::hex << _service << ":" << _instance
                      << " with minimum security level " << its_security_level
                      << " but actual level " << _security_level;
        return false;
    }

    return true;
}

} // namespace vsomeip
