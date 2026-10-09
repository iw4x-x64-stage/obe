// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <boost/asio/ssl/context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/auth.hxx>
#include <libobe/ticket.hxx>
#include <libobe/authenticator.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct auth_settings
  {
    // The titles we serve. An empty list means any title.
    //
    vector<title_id> titles;

    // The ticket lifetime. The gateway only checks it at the handshake, so
    // it is the time the client has to connect after authenticating.
    //
    duration ticket_lifetime = std::chrono::hours (1);

    // The client ticket type. The client deserializes it but never reads
    // it, so any value works (what the original server sends is not
    // known).
    //
    uint8_t ticket_type = 0;

    // The reply extra data.
    //
    string sandbox = "RETAIL";
    string platform = "PC";

    // The largest request (headers and body) and the time the client has
    // to complete the TLS handshake and send it.
    //
    size_t   max_request_size = 8192;
    duration request_timeout = std::chrono::seconds (30);
  };

  // The authentication (auth3) server.
  //
  // Serve POST /auth/ over HTTPS (see auth_request and auth_reply for the
  // message formats): verify the platform token with the authenticator and
  // issue the tickets. The application-level failures are replied to with
  // the 200 status and an error reply (that's what the client expects), the
  // HTTP-level ones (wrong target, method, or request size) with the
  // corresponding status.
  //
  // The server, the TLS context, the authenticator, and the sealer should
  // outlive the connections, which means the io_context should be stopped
  // (and its handlers destroyed) before they are destroyed.
  //
  class LIBOBE_SYMEXPORT auth_server
  {
  public:
    using tcp = boost::asio::ip::tcp;

    // Bind to the endpoint and start listening. Throw boost::system::
    // system_error on failure.
    //
    auth_server (const boost::asio::any_io_executor&,
                 const tcp::endpoint&,
                 boost::asio::ssl::context&,
                 authenticator&,
                 const ticket_sealer&,
                 auth_settings);

    auth_server (const auth_server&) = delete;
    auth_server& operator= (const auth_server&) = delete;

    tcp::endpoint
    endpoint () const;

    // Accept the connections and serve them, each on its own coroutine,
    // until the acceptor is closed or the operation is cancelled.
    //
    boost::asio::awaitable<void>
    run ();

    // Stop accepting new connections.
    //
    void
    close ();

  private:
    boost::asio::awaitable<void>
    serve (tcp::socket);

    // Authenticate the request and return the reply.
    //
    boost::asio::awaitable<auth_reply>
    authenticate (const string& name, const string& body, string token);

  private:
    tcp::acceptor              acceptor_;
    boost::asio::ssl::context& tls_;
    authenticator&             authenticator_;
    const ticket_sealer&       sealer_;
    const auth_settings        settings_;
  };
}
