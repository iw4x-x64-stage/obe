// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <string>
#include <vector>
#include <cstdint>
#include <utility>   // to_underlying()
#include <print>
#include <iostream>
#include <exception>
#include <stdexcept> // runtime_error, invalid_argument

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <libobe/auth.hxx>
#include <libobe/ticket.hxx>
#include <libobe/auth-server.hxx>
#include <libobe/authenticator.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

using asio::awaitable;
using asio::use_awaitable;
using asio::ip::tcp;

// Accept the tokens of the form 'user:<id>:<name>', deny 'deny', reject
// 'forged' as invalid, and fail on anything else.
//
class token_authenticator: public authenticator
{
public:
  virtual awaitable<optional<auth_identity>>
  authenticate (string token, title_id) override
  {
    if (token == "deny")
      co_return nullopt;

    if (token == "forged")
      throw invalid_argument ("bad signature");

    if (!token.starts_with ("user:"))
      throw runtime_error ("platform unavailable");

    const size_t p (token.find (':', 5));
    assert (p != string::npos);

    co_return auth_identity {user_id {stoull (token.substr (5, p - 5))},
                             license_id {7},
                             token.substr (p + 1)};
  }
};

// Usage: argv[0] <certificate> <key>
//
// Run the authentication server on the loopback interface with the
// certificate and key, read requests from stdin, one per line, send each
// over a new connection, and print the response:
//
// <method> <target> <token> [<body>]
//
// A token or body of the form '*<n>' stands for n 'x' characters (to test
// the size limits).
//
// The response is printed as the HTTP status code followed, for the 200
// status, by the reply code and, for grants, by the iv seed, the client
// ticket's user id, user name, title id, the server ticket's user id,
// whether the session keys in the tickets match, and the extra data.
//
// The server only serves title 1234. Its diagnostics go to stderr.
//
int
main (int argc, char* argv[])
{
  if (argc != 3)
  {
    println (cerr, "usage: {} <certificate> <key>", argv[0]);
    return 1;
  }

  asio::ssl::context stls (asio::ssl::context::tls_server);
  stls.use_certificate_chain_file (argv[1]);
  stls.use_private_key_file (argv[2], asio::ssl::context::pem);

  asio::ssl::context ctls (asio::ssl::context::tls_client);
  ctls.set_verify_mode (asio::ssl::verify_none);

  ticket_key tk {};
  const ticket_sealer sealer (tk);

  token_authenticator auth;

  auth_settings settings;
  settings.titles = {title_id {1234}};

  asio::io_context ctx;
  auth_server server (ctx.get_executor (),
                      tcp::endpoint (asio::ip::address_v4::loopback (), 0),
                      stls,
                      auth,
                      sealer,
                      settings);

  asio::co_spawn (ctx, server.run (), asio::detached);

  vector<string> requests;
  for (string l; getline (cin, l); )
    requests.push_back (move (l));

  // Send the requests.
  //
  auto play = [&server, &ctls, &sealer, &requests] () -> awaitable<void>
  {
    for (const string& l: requests)
    {
      istringstream is (l);
      string method, target, token, body;
      is >> method >> target >> token;
      if (is.get () == ' ')
        getline (is, body);

      auto expand = [] (string& s)
      {
        if (s.size () > 1 && s[0] == '*')
          s = string (stoul (s.substr (1)), 'x');
      };

      expand (token);
      expand (body);

      beast::ssl_stream<beast::tcp_stream> s (
        co_await asio::this_coro::executor, ctls);

      co_await beast::get_lowest_layer (s).async_connect (server.endpoint (),
                                                          use_awaitable);
      co_await s.async_handshake (asio::ssl::stream_base::client,
                                  use_awaitable);

      http::request<http::string_body> rq (http::string_to_verb (method),
                                           target,
                                           11);
      rq.set (http::field::host, "localhost");
      rq.set (http::field::content_type, "application/json");
      rq.set (http::field::authorization, token);
      rq.set ("X-TransactionID", "1");
      rq.keep_alive (false);
      rq.body () = body;
      rq.prepare_payload ();

      co_await http::async_write (s, rq, use_awaitable);

      beast::flat_buffer b;
      http::response<http::string_body> rs;
      co_await http::async_read (s, b, rs, use_awaitable);

      print ("{}", rs.result_int ());

      if (rs.result () == http::status::ok)
      {
        const auth_reply r (rs.body ());
        print (" code {}", r.code);

        if (r.grant)
        {
          const client_ticket c (r.grant->client);
          const server_ticket t (sealer.open (r.grant->server));

          print (" iv {} user {} name {} title {} server-user {} key {} {} {}",
                 r.grant->iv_seed,
                 to_underlying (c.user),
                 c.user_name,
                 to_underlying (c.title),
                 to_underlying (t.user),
                 c.key == t.key ? "match" : "mismatch",
                 r.grant->sandbox,
                 r.grant->platform);
        }
      }

      println ();

      co_await s.async_shutdown (asio::as_tuple (use_awaitable));
    }
  };

  int r (0);
  asio::co_spawn (ctx, play (), [&server, &r] (exception_ptr e)
  {
    if (e)
    {
      try
      {
        rethrow_exception (e);
      }
      catch (const std::exception& x)
      {
        println (cerr, "error: {}", x.what ());
      }
      r = 1;
    }

    server.close ();
  });

  ctx.run ();
  return r;
}
