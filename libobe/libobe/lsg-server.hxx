// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/ticket.hxx>
#include <libobe/service.hxx>
#include <libobe/lsg-registry.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct lsg_settings
  {
    // The largest client frame accepted (the size field value).
    //
    size_t max_frame_size = 0x10000;

    // The time the client has to send the prelude and the handshake.
    //
    duration handshake_timeout = std::chrono::seconds (30);

    // The connection is closed if nothing is received for this long. The
    // client sends a keepalive after 90 seconds of not sending anything.
    //
    duration idle_timeout = std::chrono::seconds (180);

    // A keepalive is sent if nothing was sent for this long. The client
    // closes the connection after 180 seconds of not receiving anything.
    //
    duration keepalive_interval = std::chrono::seconds (60);

    // The number of frames that can be queued for sending on a connection.
    // The task replies wait for room while the push messages that don't
    // fit are dropped.
    //
    size_t send_queue_size = 64;
  };

  // The lobby service gateway server.
  //
  // The connection starts with the prelude (see frame_prelude) followed by
  // the handshake frame, a plain frame with the following payload:
  //
  // uint8      7           (raw byte before the buffer)
  // uint32     title id
  // uint32     initial seed (0 if the client doesn't encrypt)
  // bits[1024] server ticket
  //
  // We open the server ticket (see ticket_sealer), verify that it's not
  // expired and is for the title, and reply with the connection id frame. On
  // failure we reply with the gateway error frame and close the connection.
  // After the handshake the client sends tasks (see service) and the
  // connection is attached to the registry so that the services can push
  // messages to it.
  //
  // The server must be run by a single thread (see service). The
  // diagnostics (failed handshakes and tasks, misbehaving clients) are
  // printed to stderr.
  //
  // The server, the sealer, the services, and the registry should outlive
  // the connections, which means the io_context should be stopped (and its
  // handlers destroyed) before they are destroyed.
  //
  class LIBOBE_SYMEXPORT lsg_server
  {
  public:
    using tcp = boost::asio::ip::tcp;

    // Bind to the endpoint and start listening. Throw boost::system::
    // system_error on failure.
    //
    lsg_server (const boost::asio::any_io_executor&,
                const tcp::endpoint&,
                const ticket_sealer&,
                const service_map&,
                lsg_registry&,
                lsg_settings);

    lsg_server (const lsg_server&) = delete;
    lsg_server& operator= (const lsg_server&) = delete;

    // Return the local endpoint (useful if bound to port 0).
    //
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
    class session;

    // Serve the connection. The session lives in the coroutine frame.
    //
    boost::asio::awaitable<void>
    serve (tcp::socket);

    tcp::acceptor          acceptor_;
    const ticket_sealer&   sealer_;
    const service_map&     services_;
    lsg_registry&          registry_;
    const lsg_settings     settings_;
    uint64_t               connection_; // Last connection id.
  };
}
