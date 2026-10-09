// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <boost/asio/awaitable.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The authenticated client identity.
  //
  struct auth_identity
  {
    user_id    user;
    license_id license;
    string     user_name; // At most client_ticket::max_user_name characters.
  };

  // The platform token verification.
  //
  // The client presents a platform token (the Authorization header value)
  // which the authentication server passes to the authenticator together
  // with the title id from the request. This is the seam where the platform
  // (for example, the Xbox or Steam services) is consulted, so it is a
  // coroutine.
  //
  // The authenticator is shared by all the connections, so if the
  // io_context is run by several threads, then authenticate() can be called
  // concurrently and must be MT-safe.
  //
  class LIBOBE_SYMEXPORT authenticator
  {
  public:
    // Return the identity or nullopt if the token is not valid for the
    // title. Exceptions other than std::bad_alloc are treated as transient
    // failures (the client gets a server error and may retry).
    //
    virtual boost::asio::awaitable<optional<auth_identity>>
    authenticate (string token, title_id) = 0;

    authenticator () = default;

    virtual
    ~authenticator ();

    authenticator (const authenticator&) = delete;
    authenticator& operator= (const authenticator&) = delete;
  };
}
