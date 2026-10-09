// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/auth-server.hxx>

#include <print>
#include <cstdio> // stderr
#include <sstream>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

using namespace std;

namespace obe
{
  namespace asio = boost::asio;
  namespace beast = boost::beast;
  namespace http = beast::http;

  using asio::awaitable;
  using asio::use_awaitable;
  using asio::ip::tcp;

  static const char auth_target[] = "/auth/";

  // The delay before accepting again after a failure.
  //
  static const chrono::seconds accept_retry_delay (1);

  auth_server::
  auth_server (const asio::any_io_executor& ex,
               const tcp::endpoint& ep,
               asio::ssl::context& t,
               authenticator& a,
               const ticket_sealer& s,
               auth_settings st)
    : acceptor_ (ex, ep),
      tls_ (t),
      authenticator_ (a),
      sealer_ (s),
      settings_ (move (st))
  {
  }

  tcp::endpoint auth_server::
  endpoint () const
  {
    return acceptor_.local_endpoint ();
  }

  void auth_server::
  close ()
  {
    boost::system::error_code ec;
    acceptor_.close (ec);
  }

  awaitable<auth_reply> auth_server::
  authenticate (const string& n, const string& body, string token)
  {
    // Parse and validate the request.
    //
    optional<auth_request> rq;
    try
    {
      rq = auth_request (body);
    }
    catch (const invalid_argument& e)
    {
      println (stderr, "{}: warning: {}", n, e.what ());
      co_return auth_reply (auth_code::bad_request);
    }

    const vector<title_id>& ts (settings_.titles);
    if (!ts.empty () && !ranges::contains (ts, rq->title))
    {
      println (stderr,
               "{}: warning: title {} not served",
               n, to_underlying (rq->title));
      co_return auth_reply (auth_code::bad_title);
    }

    // Verify the token. Note that we cannot co_await in the handler.
    //
    optional<auth_identity> id;
    bool failed (false);
    try
    {
      id = co_await authenticator_.authenticate (move (token), rq->title);
    }
    catch (const bad_alloc&)
    {
      throw;
    }
    catch (const std::exception& e)
    {
      println (stderr, "{}: error: unable to authenticate: {}", n, e.what ());
      failed = true;
    }

    if (failed)
      co_return auth_reply (auth_code::server_error);

    if (!id)
    {
      println (stderr, "{}: warning: authentication denied", n);
      co_return auth_reply (auth_code::bad_account);
    }

    // Issue the tickets.
    //
    const timestamp now (system_clock::now ());
    const timestamp expires (now + settings_.ticket_lifetime);
    const session_key key (generate_session_key ());

    auth_grant g;
    g.iv_seed = rq->iv_seed;
    g.sandbox = settings_.sandbox;
    g.platform = settings_.platform;

    g.client = client_ticket (settings_.ticket_type,
                              rq->title,
                              now,
                              expires,
                              id->license,
                              id->user,
                              id->user_name,
                              key).binary ();

    g.server = sealer_.seal (server_ticket {rq->title,
                                            now,
                                            expires,
                                            id->license,
                                            id->user,
                                            key});

    println (stderr,
             "{}: info: authenticated user {} ({}) for title {}",
             n,
             to_underlying (id->user),
             id->user_name,
             to_underlying (rq->title));

    co_return auth_reply (move (g));
  }

  awaitable<void> auth_server::
  serve (tcp::socket s)
  {
    string n;
    {
      boost::system::error_code ec;
      const tcp::endpoint e (s.remote_endpoint (ec));

      ostringstream os;
      if (ec)
        os << "<unknown>";
      else
        os << e;
      n = os.str ();
    }

    beast::ssl_stream<beast::tcp_stream> ts (move (s), tls_);

    // Each operation (the TLS handshake, the request read, the response
    // write) has the same time limit.
    //
    beast::get_lowest_layer (ts).expires_after (settings_.request_timeout);
    co_await ts.async_handshake (asio::ssl::stream_base::server,
                                 use_awaitable);

    beast::flat_buffer b;
    for (;;)
    {
      // Read the request.
      //
      http::request_parser<http::string_body> p;
      p.header_limit (static_cast<uint32_t> (settings_.max_request_size));
      p.body_limit (settings_.max_request_size);

      beast::get_lowest_layer (ts).expires_after (settings_.request_timeout);

      auto [ec, _] (
        co_await http::async_read (ts, b, p, asio::as_tuple (use_awaitable)));

      if (ec == http::error::end_of_stream)
        break;

      // Reply to a request that exceeds the size limits and close the
      // connection since we cannot resynchronize with the rest of the
      // request.
      //
      if (ec == http::error::header_limit || ec == http::error::body_limit)
      {
        println (stderr, "{}: warning: request too large", n);

        http::response<http::string_body> rs (
          ec == http::error::header_limit
          ? http::status::request_header_fields_too_large
          : http::status::payload_too_large,
          11 /* HTTP/1.1 */);

        rs.set (http::field::server, "obe");
        rs.keep_alive (false);
        rs.prepare_payload ();

        beast::get_lowest_layer (ts).expires_after (settings_.request_timeout);
        co_await http::async_write (ts, rs, use_awaitable);
        break;
      }

      if (ec)
        throw boost::system::system_error (ec);

      const http::request<http::string_body>& rq (p.get ());

      // Prepare the response.
      //
      http::response<http::string_body> rs;
      rs.version (rq.version ());
      rs.keep_alive (rq.keep_alive ());
      rs.set (http::field::server, "obe");

      if (rq.target () != auth_target)
      {
        rs.result (http::status::not_found);
      }
      else if (rq.method () != http::verb::post)
      {
        rs.result (http::status::method_not_allowed);
        rs.set (http::field::allow, "POST");
      }
      else
      {
        const auth_reply r (
          co_await authenticate (n,
                                 rq.body (),
                                 string (rq[http::field::authorization])));

        rs.result (http::status::ok);
        rs.set (http::field::content_type, "application/json");
        rs.body () = r.json ();
      }

      rs.prepare_payload ();

      beast::get_lowest_layer (ts).expires_after (settings_.request_timeout);
      co_await http::async_write (ts, rs, use_awaitable);

      if (!rs.keep_alive ())
        break;
    }

    // Shut down TLS gracefully. The client may just drop the connection, so
    // ignore any errors.
    //
    beast::get_lowest_layer (ts).expires_after (settings_.request_timeout);
    co_await ts.async_shutdown (asio::as_tuple (use_awaitable));
  }

  awaitable<void> auth_server::
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

      auto report = [] (exception_ptr e)
      {
        if (!e)
          return;

        // Network and TLS errors are routine (the client went away, etc),
        // so we keep quiet about them.
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
