// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service-messaging.hxx>

using namespace std;

namespace obe
{
  // The custom friend message type.
  //
  static const uint32_t friend_custom_message (40);

  messaging_service::
  messaging_service (lsg_registry& r, name_function n, messaging_settings s)
    : registry_ (r),
      name_ (move (n)),
      settings_ (move (s))
  {
    LIBOBE_PRE (name_ != nullptr);
  }

  awaitable<void> messaging_service::
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer&)
  {
    if (op != 8)
      throw task_error (lsg_error::service_not_available,
                        "messaging operation {} not supported", op);

    // Parse the request.
    //
    in.next_uint8 (); // Reserved.

    const bytes m (in.next_blob (max_message));
    const uint32_t field (in.next_uint32 ());
    const bool single (in.next_bool ());

    vector<user_id> rs;
    while (in.peek () == bit_type::uint64)
    {
      if (rs.size () == settings_.max_recipients)
        throw task_error (lsg_error::messaging_send_quota_exceeded,
                          "more than {} recipients",
                          settings_.max_recipients);

      rs.push_back (user_id {in.next_uint64 ()});

      if (single)
        break;
    }

    if (rs.empty ())
      throw task_error (lsg_error::parameter_parse_error, "no recipients");

    // Push the message to each recipient. The name is cut at the first
    // '\0' (which a string cannot contain) and truncated rather than
    // rejected since it's not the client's fault.
    //
    string n (name_ (id.user));
    n.resize (min ({n.find ('\0'), n.size (), max_name}));

    for (user_id r: rs)
    {
      bytes p;
      {
        bit_serializer s (p);
        s.next_uint32 (friend_custom_message);
        s.next_uint64 (to_underlying (r));
        s.next_uint64 (++last_message_);
        s.next_uint32 (field);
        s.next_bool (false);
        s.next_uint64 (to_underlying (id.user));
        s.next_string (n);
        s.next_blob (m);
      }

      registry_.push (id.title, r, p);
    }

    co_return;
  }
}
