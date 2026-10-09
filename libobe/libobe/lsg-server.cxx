// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/lsg-server.hxx>

#include <print>
#include <random>
#include <cstdio>  // stderr
#include <sstream>
#include <variant>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <libobe/frame.hxx>
#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>

using namespace std;

namespace obe
{
  namespace asio = boost::asio;

  using asio::awaitable;
  using asio::use_awaitable;
  using asio::ip::tcp;

  using namespace asio::experimental::awaitable_operators;

  using steady = chrono::steady_clock;

  // The handshake pseudo-service id.
  //
  static const uint8_t handshake_service (7);

  // The client drops frames larger than its receive capacity minus this.
  //
  static const size_t receive_reserve (10);

  // The delay before accepting again after a failure.
  //
  static const chrono::seconds accept_retry_delay (1);

  // Serialize the task error reply.
  //
  static bytes
  error_reply (uint64_t transaction, lsg_error e)
  {
    bytes r;
    bit_serializer s (r);
    s.next_uint64 (transaction);
    s.next_uint32 (to_underlying (e));
    return r;
  }

  // lsg_server::session
  //
  class lsg_server::session
  {
  public:
    session (lsg_server&, tcp::socket);

    // Detach from the registry and notify the services.
    //
    ~session ();

    session (const session&) = delete;
    session& operator= (const session&) = delete;

    // Serve the connection until it is closed by either side.
    //
    awaitable<void>
    run ();

  private:
    // An outgoing message: a frame, a keepalive, or the end of the stream
    // (which stops the transmitter).
    //
    struct message
    {
      enum class kind_type {frame, keepalive, end};

      kind_type  kind;
      frame_type type = frame_type::task_reply;
      bytes      payload;
    };

    using queue_type = asio::experimental::channel<
      void (boost::system::error_code, message)>;

    // Read some data into the buffer unless the deadline passes first.
    // Return the number of bytes read (0 on EOF) or nullopt on timeout.
    //
    awaitable<optional<size_t>>
    read_some (span<uint8_t>, steady::time_point deadline);

    // Read the prelude. Return false if the connection is closed or timed
    // out.
    //
    awaitable<bool>
    prelude ();

    // Return the next frame or nullopt if the connection is closed or timed
    // out. Queue keepalives while waiting.
    //
    awaitable<optional<frame>>
    next_frame ();

    // Verify the handshake and establish the identity. Throw task_error
    // with the gateway error code on failure.
    //
    lsg_identity
    verify (const frame&);

    // Perform the handshake. Return false on failure.
    //
    awaitable<bool>
    handshake (const frame&);

    // Receive and handle the tasks until the connection is closed, then
    // queue the end of the stream.
    //
    awaitable<void>
    receive ();

    // Send the queued messages until the end of the stream.
    //
    awaitable<void>
    transmit ();

    // Handle the task and queue the reply.
    //
    awaitable<void>
    task (const frame&);

    // Queue the message, waiting for room if the queue is full.
    //
    awaitable<void>
    enqueue (message);

    // Queue the push message unless the queue is full or the client won't
    // accept it. Return false if it was dropped.
    //
    bool
    push (const bytes&);

    // Send the frame right away, encrypted if the client encrypts.
    //
    awaitable<void>
    send (frame_type, span<const uint8_t> payload);

    awaitable<void>
    send_keepalive ();

    // Return true if the client accepts a frame with the payload of the
    // specified size.
    //
    bool
    acceptable (size_t payload) const noexcept;

  private:
    lsg_server&    server_;
    tcp::socket    socket_;
    const string   name_; // Peer endpoint for diagnostics.
    frame_parser   parser_;
    queue_type     queue_;

    optional<frame_prelude> prelude_;
    optional<lsg_identity>  identity_;
    optional<frame_cipher>  cipher_;
    bool                    encrypt_;

    uint32_t seed_;        // Next server frame seed.
    uint64_t transaction_; // Last transaction id.

    steady::time_point last_receive_;
    steady::time_point last_send_;    // Last sent or queued.

    // Note: must be destroyed before the queue (the sink refers to it).
    //
    lsg_registry::registration registration_;
  };

  // Return the peer endpoint as a string or "<unknown>" if it is no longer
  // available.
  //
  static string
  peer (const tcp::socket& s)
  {
    boost::system::error_code ec;
    const tcp::endpoint e (s.remote_endpoint (ec));

    if (ec)
      return "<unknown>";

    ostringstream os;
    os << e;
    return os.str ();
  }

  lsg_server::session::
  session (lsg_server& s, tcp::socket k)
    : server_ (s),
      socket_ (move (k)),
      name_ (peer (socket_)),
      parser_ (name_, s.settings_.max_frame_size),
      queue_ (socket_.get_executor (), s.settings_.send_queue_size),
      encrypt_ (false),
      seed_ (random_device () ()),
      transaction_ (0),
      last_receive_ (steady::now ()),
      last_send_ (last_receive_)
  {
  }

  lsg_server::session::
  ~session ()
  {
    // Stop the pushes before letting the services forget the connection.
    //
    registration_.reset ();

    if (identity_)
    {
      for (const auto& [id, s]: server_.services_)
        s.get ().disconnect (*identity_);
    }
  }

  awaitable<optional<size_t>> lsg_server::session::
  read_some (span<uint8_t> b, steady::time_point d)
  {
    asio::steady_timer t (socket_.get_executor (), d);

    variant<tuple<boost::system::error_code, size_t>,
            tuple<boost::system::error_code>> r (
      co_await (socket_.async_read_some (asio::buffer (b.data (), b.size ()),
                                         asio::as_tuple (use_awaitable)) ||
                t.async_wait (asio::as_tuple (use_awaitable))));

    if (r.index () == 1)
      co_return nullopt;

    const auto [ec, n] (get<0> (r));

    if (ec == asio::error::eof)
      co_return 0;

    if (ec)
      throw boost::system::system_error (ec);

    last_receive_ = steady::now ();
    co_return n;
  }

  awaitable<bool> lsg_server::session::
  prelude ()
  {
    const steady::time_point d (last_receive_ +
                                server_.settings_.handshake_timeout);

    array<uint8_t, frame_prelude::size> b;
    for (size_t n (0); n != b.size (); )
    {
      const optional<size_t> r (
        co_await read_some (span (b).subspan (n), d));

      if (!r)
      {
        println (stderr, "{}: warning: timed out waiting for prelude", name_);
        co_return false;
      }

      if (*r == 0)
        co_return false;

      n += *r;
    }

    // Note: throws invalid_argument (handled by the caller).
    //
    prelude_.emplace (b);
    co_return true;
  }

  awaitable<optional<frame>> lsg_server::session::
  next_frame ()
  {
    const lsg_settings& s (server_.settings_);

    for (;;)
    {
      if (optional<frame> f = parser_.next (cipher_ ? &*cipher_ : nullptr))
        co_return f;

      // Figure out how long we can wait: until the idle timeout and, after
      // the handshake, until the next keepalive is due.
      //
      const duration idle (identity_ ? s.idle_timeout : s.handshake_timeout);

      steady::time_point d (last_receive_ + idle);
      if (identity_)
        d = min (d, last_send_ + s.keepalive_interval);

      array<uint8_t, 4096> b;
      const optional<size_t> n (co_await read_some (b, d));

      if (!n)
      {
        if (steady::now () >= last_receive_ + idle)
        {
          println (stderr, "{}: info: connection idle, closing", name_);
          co_return nullopt;
        }

        co_await enqueue (message {message::kind_type::keepalive, {}, {}});
        continue;
      }

      if (*n == 0)
        co_return nullopt;

      parser_.append (span (b.data (), *n));
    }
  }

  lsg_identity lsg_server::session::
  verify (const frame& f)
  {
    const span<const uint8_t> p (f.payload);

    if (p.empty () || p[0] != handshake_service)
      throw task_error (lsg_error::protocol_error, "invalid handshake frame");

    // Parse the handshake.
    //
    title_id title;
    uint32_t seed;
    ticket_data d;
    try
    {
      bit_parser in (p.subspan (1), name_);

      if (!in.typed ())
        throw task_error (lsg_error::protocol_error,
                          "untyped handshake buffer");

      title = title_id {in.next_uint32 ()};
      seed = in.next_uint32 ();
      in.next_bytes (d);
    }
    catch (const bit_parsing& e)
    {
      throw task_error (lsg_error::protocol_error,
                        "invalid handshake: {}", e.description);
    }

    // Open and verify the ticket.
    //
    server_ticket t;
    try
    {
      t = server_.sealer_.open (d);
    }
    catch (const invalid_argument& e)
    {
      throw task_error (lsg_error::access_denied, "{}", e.what ());
    }

    if (t.expired (system_clock::now ()))
      throw task_error (lsg_error::access_denied, "server ticket expired");

    if (t.title != title)
      throw task_error (lsg_error::access_denied,
                        "server ticket is for title {} instead of {}",
                        to_underlying (t.title), to_underlying (title));

    // Switch to the session key. A zero seed means the client won't encrypt
    // its frames and so we won't either.
    //
    cipher_.emplace (t.key);
    encrypt_ = seed != 0;

    // Note that the local endpoint is only unavailable if the connection is
    // gone, in which case the address doesn't matter.
    //
    boost::system::error_code ec;
    const tcp::endpoint le (socket_.local_endpoint (ec));

    return lsg_identity {t.user,
                         t.title,
                         t.license,
                         ++server_.connection_,
                         le.address ()};
  }

  awaitable<bool> lsg_server::session::
  handshake (const frame& f)
  {
    // Note that we cannot co_await in the handler.
    //
    optional<task_error> e;
    try
    {
      identity_ = verify (f);
    }
    catch (const task_error& x)
    {
      e = x;
    }

    if (e)
    {
      println (stderr,
               "{}: warning: handshake failed: {} ({})",
               name_, e->what (), e->code);

      bytes b;
      bit_serializer s (b);
      s.next_uint32 (to_underlying (e->code));

      co_await send (frame_type::error, b);
      co_return false;
    }

    println (stderr,
             "{}: info: user {} connected as {}",
             name_, to_underlying (identity_->user), identity_->connection);

    bytes b;
    bit_serializer s (b);
    s.next_uint64 (identity_->connection);

    co_await send (frame_type::connection_id, b);
    co_return true;
  }

  awaitable<void> lsg_server::session::
  receive ()
  {
    while (optional<frame> f = co_await next_frame ())
      co_await task (*f);

    co_await enqueue (message {message::kind_type::end, {}, {}});
  }

  awaitable<void> lsg_server::session::
  transmit ()
  {
    for (;;)
    {
      message m (co_await queue_.async_receive (use_awaitable));

      switch (m.kind)
      {
        case message::kind_type::frame:     co_await send (m.type, m.payload);
                                            break;
        case message::kind_type::keepalive: co_await send_keepalive ();
                                            break;
        case message::kind_type::end:       co_return;
      }
    }
  }

  awaitable<void> lsg_server::session::
  task (const frame& f)
  {
    const span<const uint8_t> p (f.payload);

    if (p.empty ())
      throw task_error (lsg_error::protocol_error, "empty task frame");

    const uint8_t id (p[0]);
    const uint64_t tx (++transaction_);

    service* s (nullptr);
    if (auto i = server_.services_.find (id); i != server_.services_.end ())
      s = &i->second.get ();

    // We treat the tasks for unknown services as bit tasks since most of
    // the services are.
    //
    const bool bit (s == nullptr || s->kind () == service::kind_type::bit);

    // Run the handler, replacing the reply with the error reply if it fails.
    //
    bytes r;
    try
    {
      if (bit)
      {
        bit_parser in (p.subspan (1), name_);

        if (!in.typed ())
          throw task_error (lsg_error::protocol_error, "untyped task buffer");

        const uint8_t op (in.next_uint8 ());

        if (s == nullptr)
          throw task_error (lsg_error::service_not_available,
                            "unknown service {}", id);

        bit_serializer out (r);
        out.next_uint64 (tx);
        out.next_uint32 (to_underlying (lsg_error::none));
        out.next_uint8 (op);

        co_await s->handle (*identity_, op, in, out);
      }
      else
      {
        // Byte replies have no error code: on failure the client gets the
        // transaction id alone.
        //
        for (size_t i (0); i != 8; ++i)
          r.push_back (static_cast<uint8_t> (tx >> (i * 8)));

        if (p.size () < 2)
          throw task_error (lsg_error::protocol_error,
                            "missing byte task operation");

        co_await s->handle (*identity_, p[1], p.subspan (2), r);
      }
    }
    catch (const task_error& e)
    {
      println (stderr,
               "{}: warning: task {} failed: {} ({})",
               name_, tx, e.what (), e.code);

      if (bit)
        r = error_reply (tx, e.code);
      else
        r.resize (8);
    }
    catch (const bit_parsing& e)
    {
      println (stderr,
               "{}: warning: task {} failed: {}",
               name_, tx, e.description);

      r = error_reply (tx, lsg_error::parameter_parse_error);
    }

    // Make sure the client will accept the reply.
    //
    if (!acceptable (r.size ()))
    {
      println (stderr,
               "{}: warning: task {} reply of {} bytes exceeds client "
               "capacity",
               name_, tx, r.size ());

      if (bit)
        r = error_reply (tx, lsg_error::result_too_large);
      else
        r.resize (8);
    }

    co_await enqueue (
      message {message::kind_type::frame,
               bit ? frame_type::task_reply : frame_type::service_reply,
               move (r)});
  }

  awaitable<void> lsg_server::session::
  enqueue (message m)
  {
    co_await queue_.async_send (boost::system::error_code (),
                                move (m),
                                use_awaitable);
    last_send_ = steady::now ();
  }

  bool lsg_server::session::
  push (const bytes& p)
  {
    if (!acceptable (p.size ()))
    {
      println (stderr,
               "{}: warning: push message of {} bytes exceeds client "
               "capacity",
               name_, p.size ());
      return false;
    }

    if (!queue_.try_send (boost::system::error_code (),
                          message {message::kind_type::frame,
                                   frame_type::push,
                                   p}))
    {
      println (stderr, "{}: warning: send queue full, push dropped", name_);
      return false;
    }

    return true;
  }

  bool lsg_server::session::
  acceptable (size_t n) const noexcept
  {
    return frame_serializer::size (n, encrypt_) <=
           prelude_->receive_capacity - receive_reserve;
  }

  awaitable<void> lsg_server::session::
  send (frame_type t, span<const uint8_t> p)
  {
    bytes b;
    frame_serializer s (b);

    if (encrypt_)
      s.next (t, p, *cipher_, seed_++);
    else
      s.next (t, p);

    co_await asio::async_write (socket_, asio::buffer (b), use_awaitable);
    last_send_ = steady::now ();
  }

  awaitable<void> lsg_server::session::
  send_keepalive ()
  {
    bytes b;
    frame_serializer (b).next_keepalive ();

    co_await asio::async_write (socket_, asio::buffer (b), use_awaitable);
    last_send_ = steady::now ();
  }

  awaitable<void> lsg_server::session::
  run ()
  {
    // Note that a too small receive capacity would make every reply fail
    // the size check (and wrap around in the computation), so we treat it
    // as an invalid prelude.
    //
    try
    {
      if (!co_await prelude ())
        co_return;

      if (prelude_->receive_capacity <= receive_reserve)
        throw invalid_input ("receive capacity too small");

      optional<frame> f (co_await next_frame ());

      if (!f || !co_await handshake (*f))
        co_return;

      // Now that we have the identity, make the connection reachable for
      // the pushes and serve the tasks. From here on everything we send
      // goes through the queue so that the replies, the pushes, and the
      // keepalives don't interleave on the socket. If either side fails,
      // the other is cancelled.
      //
      registration_ = server_.registry_.attach (
        *identity_,
        [this] (const bytes& p) {return push (p);});

      co_await (receive () && transmit ());
    }
    catch (const frame_parsing& e)
    {
      println (stderr, "{}: warning: {}", name_, e.description);
    }
    catch (const invalid_argument& e) // Prelude.
    {
      println (stderr, "{}: warning: invalid prelude: {}", name_, e.what ());
    }
    catch (const task_error& e) // Protocol violation outside of a task.
    {
      println (stderr, "{}: warning: {}", name_, e.what ());
    }
  }

  // lsg_server
  //
  lsg_server::
  lsg_server (const asio::any_io_executor& ex,
              const tcp::endpoint& ep,
              const ticket_sealer& sl,
              const service_map& sv,
              lsg_registry& r,
              lsg_settings st)
    : acceptor_ (ex, ep),
      sealer_ (sl),
      services_ (sv),
      registry_ (r),
      settings_ (move (st)),
      connection_ (0)
  {
  }

  tcp::endpoint lsg_server::
  endpoint () const
  {
    return acceptor_.local_endpoint ();
  }

  void lsg_server::
  close ()
  {
    boost::system::error_code ec;
    acceptor_.close (ec);
  }

  awaitable<void> lsg_server::
  serve (tcp::socket s)
  {
    session ss (*this, move (s));
    co_await ss.run ();
  }

  awaitable<void> lsg_server::
  run ()
  {
    for (;;)
    {
      auto [ec, s] (
        co_await acceptor_.async_accept (asio::as_tuple (use_awaitable)));

      if (ec == asio::error::operation_aborted)
        co_return;

      // Accept can fail for transient reasons (for example, out of file
      // descriptors), so we diagnose and carry on. But not right away: such
      // a failure is normally immediate and would repeat until the condition
      // clears, so retrying straight away would spin and flood stderr.
      //
      if (ec)
      {
        println (stderr,
                 "error: unable to accept connection: {}",
                 ec.message ());

        asio::steady_timer t (acceptor_.get_executor (), accept_retry_delay);
        co_await t.async_wait (asio::as_tuple (use_awaitable));

        // Bail out if we were closed while waiting.
        //
        if (!acceptor_.is_open ())
          co_return;

        continue;
      }

      // Serve the connection on its own coroutine.
      //
      auto report = [] (exception_ptr e)
      {
        if (!e)
          return;

        // Network errors are routine (the client went away, etc), so we
        // keep quiet about them.
        //
        try
        {
          rethrow_exception (e);
        }
        catch (const boost::system::system_error&)
        {
        }
        catch (const std::exception& x)
        {
          println (stderr, "error: connection: {}", x.what ());
        }
      };

      asio::co_spawn (acceptor_.get_executor (), serve (move (s)), report);
    }
  }
}
