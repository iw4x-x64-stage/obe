// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <map>
#include <functional> // move_only_function

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/service.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The connected gateway clients.
  //
  // The gateway attaches each connection once it has completed the
  // handshake and detaches it when it closes. The services use the registry
  // to push messages (the push frames) to the users' clients without
  // knowing anything about the connections.
  //
  // The registry is not MT-safe: like the gateway and the services, it is
  // confined to the thread that runs the io_context (see service). It
  // should outlive the gateway and the services that use it.
  //
  class LIBOBE_SYMEXPORT lsg_registry
  {
  public:
    // Queue the push frame payload for sending on the connection. Return
    // false if the connection cannot take it (for example, its queue is
    // full).
    //
    // The sink must not block and must not call back into the registry.
    //
    using sink = std::move_only_function<bool (const bytes&)>;

    // The connection's registration. Detaches the connection when
    // destroyed.
    //
    class LIBOBE_SYMEXPORT registration
    {
    public:
      registration () = default;

      registration (registration&&) noexcept;
      registration& operator= (registration&&) noexcept;

      registration (const registration&) = delete;
      registration& operator= (const registration&) = delete;

      ~registration ();

      // Detach the connection now.
      //
      void
      reset () noexcept;

    private:
      friend class lsg_registry;

      registration (lsg_registry&, const lsg_identity&);

      lsg_registry* registry_ = nullptr;
      title_id      title_ {};
      user_id       user_ {};
      uint64_t      connection_ = 0;
    };

    lsg_registry () = default;

    lsg_registry (const lsg_registry&) = delete;
    lsg_registry& operator= (const lsg_registry&) = delete;

    // Attach the connection. The connection id must be unique.
    //
    registration
    attach (const lsg_identity&, sink);

    // Push the message to every connection of the user for the title.
    // Return the number of connections it was queued on.
    //
    size_t
    push (title_id, user_id, const bytes& payload);

  private:
    void
    detach (title_id, user_id, uint64_t connection) noexcept;

    using key = pair<title_id, user_id>;

    std::map<key, std::map<uint64_t, sink>> sinks_; // By connection id.
  };
}
