// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <functional> // move_only_function

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/service.hxx>
#include <libobe/lsg-registry.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct messaging_settings
  {
    // The most recipients of a message.
    //
    size_t max_recipients = 16;
  };

  // The messaging service (bdMessaging, service 6).
  //
  // The title uses it to send the game invites. The only operation is:
  //
  // 8 send  uchar8 0 (presumably reserved), blob message, uint32 field,
  //         bool single, and the uint64 recipient ids (one if single). No
  //         results.
  //
  // We push the message to every connection of each recipient as the
  // custom friend message (bdFriendCustomMessage), the push frame payload:
  //
  // uint32  message type   (40)
  // uint64  recipient id   (ignored by the client)
  // uint64  message id     (the client ignores duplicates)
  // uint32  field          (from the request)
  // bool    false          (meaning unknown)
  // uint64  sender id
  // string  sender name
  // blob    message
  //
  // Note that the message is only delivered to the recipients that are
  // connected: we don't store messages.
  //
  class LIBOBE_SYMEXPORT messaging_service: public service
  {
  public:
    // Return the name of the user (empty if unknown).
    //
    using name_function = std::move_only_function<string (user_id)>;

    // The largest message the client accepts (larger ones overflow its
    // buffer).
    //
    static constexpr size_t max_message = 1024;

    // The longest sender name the client accepts.
    //
    static constexpr size_t max_name = 63;

    // The registry should outlive the service.
    //
    messaging_service (lsg_registry&, name_function, messaging_settings = {});

    virtual kind_type
    kind () const noexcept override {return kind_type::bit;}

    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            bit_parser&,
            bit_serializer&) override;

  private:
    lsg_registry&            registry_;
    name_function            name_;
    const messaging_settings settings_;
    uint64_t                 last_message_ = 0; // Last message id.
  };
}
