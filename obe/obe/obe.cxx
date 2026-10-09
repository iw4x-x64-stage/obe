// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <map>
#include <print>
#include <format>
#include <memory>    // unique_ptr, make_unique()
#include <string>
#include <vector>
#include <cstdio>    // fflush(), stdout
#include <cstdint>
#include <csignal>   // SIGINT, SIGTERM
#include <fstream>
#include <charconv>  // from_chars()
#include <algorithm> // sort()
#include <filesystem>
#include <sstream>
#include <utility>   // move()
#include <optional>
#include <iostream>
#include <exception>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl/context.hpp>

#include <openssl/sha.h>

#include <libobe/version.hxx>
#include <libobe/pgsql.hxx>
#include <libobe/ticket.hxx>
#include <libobe/service.hxx>
#include <libobe/file-store.hxx>
#include <libobe/lsg-server.hxx>
#include <libobe/auth-server.hxx>
#include <libobe/lsg-registry.hxx>
#include <libobe/authenticator.hxx>
#include <libobe/authenticator-xbl.hxx>
#include <libobe/service-storage.hxx>
#include <libobe/service-bandwidth.hxx>
#include <libobe/service-messaging.hxx>
#include <libobe/performance-store.hxx>
#include <libobe/service-matchmaking.hxx>
#include <libobe/service-performance.hxx>

#include <obe/version.hxx>
#include <obe/obe-options.hxx>

using namespace std;

namespace obe
{
  namespace asio = boost::asio;

  using asio::ip::tcp;
  using asio::ip::udp;

  namespace
  {
    // Thrown to terminate the process once the diagnostics has been issued.
    //
    class failed: public std::exception {};

    // Accept any token, deriving the identity from the token itself: the
    // user id is the first 8 bytes of the token's SHA-256 digest and the
    // user name is 'user-' followed by the id in hex.
    //
    // Anyone presenting the same token is the same user, so this is only
    // suitable for development (see --insecure-authentication).
    //
    class development_authenticator: public authenticator
    {
    public:
      virtual asio::awaitable<optional<auth_identity>>
      authenticate (string token, title_id) override
      {
        // The client always sends a token, so an empty one means something
        // is off.
        //
        if (token.empty ())
          co_return nullopt;

        uint8_t md[SHA256_DIGEST_LENGTH];
        SHA256 (reinterpret_cast<const uint8_t*> (token.data ()),
                token.size (),
                md);

        uint64_t u (0);
        for (size_t i (0); i != 8; ++i)
          u |= static_cast<uint64_t> (md[i]) << (i * 8);

        co_return auth_identity {user_id {u},
                                 license_id {0},
                                 format ("user-{:016x}", u)};
      }
    };

    // Remember the names of the users authenticated by another
    // authenticator. The gateway only knows the user ids, so this is where
    // the messaging service gets the sender names from.
    //
    // Like the servers, it is confined to the thread that runs the
    // io_context.
    //
    // @@ Keep the names in the database so that they survive a restart.
    //
    class naming_authenticator: public authenticator
    {
    public:
      explicit
      naming_authenticator (authenticator& a): authenticator_ (a) {}

      virtual asio::awaitable<optional<auth_identity>>
      authenticate (string token, title_id t) override
      {
        optional<auth_identity> r (
          co_await authenticator_.authenticate (move (token), t));

        if (r)
          names_[r->user] = r->user_name;

        co_return r;
      }

      // Return the user's name or the empty string if unknown.
      //
      string
      name (user_id u) const
      {
        auto i (names_.find (u));
        return i != names_.end () ? i->second : string ();
      }

    private:
      authenticator&       authenticator_;
      map<user_id, string> names_;
    };
  }

  // The io_context that can destroy its pending handlers (the suspended
  // coroutines) before it is destroyed itself.
  //
  // The handlers refer to the servers and services, which in turn have the
  // sockets and timers of the io_context. So we destroy the handlers first,
  // then the servers and services, and the io_context last (see main()).
  //
  class context: public asio::io_context
  {
  public:
    using io_context::shutdown;
  };

  // The diagnostics verbosity (see --verbose).
  //
  static uint16_t verb (1);

  // Return the endpoint as a string (for example, 127.0.0.1:3074 or
  // [::1]:3074).
  //
  static string
  to_string (const tcp::endpoint& e)
  {
    ostringstream os;
    os << e;
    return os.str ();
  }

  static string
  to_string (const udp::endpoint& e)
  {
    ostringstream os;
    os << e;
    return os.str ();
  }

  // Return the address. Issue diagnostics and throw failed if it is
  // invalid.
  //
  static asio::ip::address
  address (const string& a, const char* what)
  {
    boost::system::error_code ec;
    const asio::ip::address r (asio::ip::make_address (a, ec));

    if (ec)
    {
      println (cerr, "error: invalid {} address '{}'", what, a);
      throw failed ();
    }

    return r;
  }

  // Read the ticket sealing key from the file or, if none is specified,
  // generate a random one. Issue diagnostics and throw failed on error.
  //
  static ticket_key
  load_ticket_key (const options& o)
  {
    if (!o.ticket_key_specified ())
    {
      try
      {
        return generate_ticket_key ();
      }
      catch (const system_error& e)
      {
        println (cerr, "error: unable to generate ticket key: {}", e.what ());
        throw failed ();
      }
    }

    const string& f (o.ticket_key ());

    ifstream is (f, ios::binary);
    if (!is)
    {
      println (cerr, "error: unable to open ticket key file {}", f);
      throw failed ();
    }

    ticket_key r;
    is.read (reinterpret_cast<char*> (r.data ()),
             static_cast<streamsize> (r.size ()));

    if (is.gcount () != static_cast<streamsize> (r.size ()) ||
        is.peek () != ifstream::traits_type::eof ())
    {
      println (cerr,
               "error: invalid ticket key file {}\n"
               "  info: ticket key must be exactly {} bytes",
               f, r.size ());
      throw failed ();
    }

    return r;
  }

  // The publisher file to publish (see --publisher-files).
  //
  struct publisher_file
  {
    title_id title;
    string   name;
    bytes    data;
  };

  // Read the publisher files from the subdirectories of the directory, each
  // named after the title id. Issue diagnostics and throw failed on error.
  //
  // Note that we sort the entries so that the files are published (and so
  // created with their ids) in the same order on every startup.
  //
  static vector<publisher_file>
  load_publisher_files (const string& d)
  {
    namespace fs = std::filesystem;

    // Return the directory entries sorted by name.
    //
    auto entries = [] (const fs::path& p)
    {
      vector<fs::path> r;
      for (const fs::directory_entry& e: fs::directory_iterator (p))
        r.push_back (e.path ());

      sort (r.begin (), r.end ());
      return r;
    };

    vector<publisher_file> r;
    try
    {
      for (const fs::path& td: entries (d))
      {
        // Parse the title id from the subdirectory name.
        //
        const string tn (td.filename ().string ());

        uint32_t t (0);
        const char* b (tn.data ());
        const char* e (b + tn.size ());
        const from_chars_result fr (from_chars (b, e, t));

        if (!fs::is_directory (td) || fr.ec != errc () || fr.ptr != e)
        {
          println (cerr,
                   "error: invalid publisher files title directory {}\n"
                   "  info: name it after the title id, for example, 2010",
                   td.string ());
          throw failed ();
        }

        // Read the title's files.
        //
        for (const fs::path& f: entries (td))
        {
          const string n (f.filename ().string ());

          if (!fs::is_regular_file (f))
          {
            println (cerr,
                     "error: publisher file {} is not a regular file",
                     f.string ());
            throw failed ();
          }

          if (n.size () > file_header::max_name)
          {
            println (cerr,
                     "error: publisher file name {} is longer than {} "
                     "characters",
                     n, file_header::max_name);
            throw failed ();
          }

          ifstream is (f, ios::binary);
          if (!is)
          {
            println (cerr,
                     "error: unable to open publisher file {}",
                     f.string ());
            throw failed ();
          }

          bytes data ((istreambuf_iterator<char> (is)),
                      istreambuf_iterator<char> ());

          if (is.bad ())
          {
            println (cerr,
                     "error: unable to read publisher file {}",
                     f.string ());
            throw failed ();
          }

          r.push_back (publisher_file {title_id {t}, n, move (data)});
        }
      }
    }
    catch (const fs::filesystem_error& e)
    {
      println (cerr,
               "error: unable to read publisher files directory {}: {}",
               e.path1 ().string (), e.code ().message ());
      throw failed ();
    }

    return r;
  }

  static int
  main (int argc, char* argv[])
  try
  {
    // Parse the command line, including the options files.
    //
    options o;
    {
      cli::argv_file_scanner s (argc, argv, "--options-file");
      o.parse (s);
    }

    // Handle --help and --version.
    //
    if (o.help ())
    {
      print_obe_usage (cout);
      return 0;
    }

    if (o.version ())
    {
      println ("obe {}\n"
               "libobe {}\n"
               "Copyright (c) the IW4x authors.\n"
               "This is free software released under the GNU General Public "
               "License, version 3,\n"
               "with the IW4x Linking Exception, version 1.1.",
               OBE_VERSION_ID,
               LIBOBE_VERSION_ID);
      return 0;
    }

    // Set the verbosity.
    //
    // Note that the more specific options override --verbose.
    //
    if (o.verbose () > 3)
    {
      println (cerr,
               "error: invalid --verbose value {}\n"
               "  info: specify a level between 0 and 3",
               o.verbose ());
      throw failed ();
    }

    verb = o.quiet () ? 0 :
           o.V ()     ? 3 :
           o.v ()     ? 2 :
           o.verbose ();

    // Open the database, if any.
    //
    // Note that the connection is only established on the first database
    // access.
    //
    if (o.migrate () && !o.db_name_specified ())
    {
      println (cerr,
               "error: no database to migrate\n"
               "  info: specify it with --db-name");
      throw failed ();
    }

    unique_ptr<pgsql_database> db;
    if (o.db_name_specified ())
    {
      if (o.db_max_connections () == 0)
      {
        println (cerr, "error: invalid --db-max-connections value 0");
        throw failed ();
      }

      pgsql_settings s;
      s.user            = o.db_user ();
      s.password        = o.db_password ();
      s.name            = o.db_name ();
      s.host            = o.db_host ();
      s.port            = o.db_port ();
      s.max_connections = o.db_max_connections ();
      s.retry           = o.db_retry ();

      db = make_unique<pgsql_database> (s);
    }

    // If requested, migrate the database schema and exit. Otherwise, make
    // sure the schema is current: the server of one version should not touch
    // the schema of another.
    //
    if (db != nullptr)
    {
      const string& n (o.db_name ());
      const uint64_t cv (db->current_schema_version ());

      if (o.migrate ())
      {
        uint64_t v;
        try
        {
          v = db->migrate ();
        }
        catch (const database_error& e)
        {
          println (cerr, "error: unable to migrate database {}: {}",
                   n, e.what ());
          throw failed ();
        }

        if (verb >= 2)
        {
          if (v == 0)
            println (cerr, "created database {} schema version {}", n, cv);
          else if (v != cv)
            println (cerr,
                     "migrated database {} schema from version {} to {}",
                     n, v, cv);
          else
            println (cerr, "database {} schema version {} is current",
                     n, cv);
        }

        return 0;
      }

      uint64_t v;
      try
      {
        v = db->schema_version ();
      }
      catch (const database_error& e)
      {
        println (cerr, "error: unable to access database {}: {}",
                 n, e.what ());
        throw failed ();
      }

      if (v != cv)
      {
        if (v == 0)
          println (cerr, "error: database {} has no schema", n);
        else
          println (cerr,
                   "error: database {} schema version {} instead of {}",
                   n, v, cv);

        println (cerr, "  info: run 'obe --migrate' to create or migrate it");
        throw failed ();
      }
    }

    // Verify the server configuration.
    //
    if (!o.tls_certificate_specified () || !o.tls_key_specified ())
    {
      println (cerr,
               "error: TLS certificate and key are required\n"
               "  info: specify them with --tls-certificate and --tls-key");
      throw failed ();
    }

    // Load the publisher files, if any.
    //
    const vector<publisher_file> pfs (
      o.publisher_files_specified ()
      ? load_publisher_files (o.publisher_files ())
      : vector<publisher_file> ());

    const tcp::endpoint ae (
      address (o.auth_address (), "authentication"), o.auth_port ());

    const tcp::endpoint ge (
      address (o.lsg_address (), "gateway"), o.lsg_port ());

    const udp::endpoint be (
      address (o.bandwidth_address (), "bandwidth test"), o.bandwidth_port ());

    // The clients only take an IPv4 address for the bandwidth test.
    //
    bandwidth_settings bs;
    bs.public_port = o.bandwidth_public_port ();

    if (o.bandwidth_public_address_specified ())
    {
      const string& a (o.bandwidth_public_address ());
      const asio::ip::address pa (address (a, "bandwidth test public"));

      if (!pa.is_v4 () || pa.is_unspecified ())
      {
        println (cerr,
                 "error: invalid bandwidth test public address '{}'\n"
                 "  info: specify the IPv4 address the clients can reach",
                 a);
        throw failed ();
      }

      bs.public_address = pa.to_v4 ();
    }

    // Load the TLS certificate and key of the authentication server.
    //
    asio::ssl::context tls (asio::ssl::context::tls_server);
    try
    {
      tls.use_certificate_chain_file (o.tls_certificate ());
      tls.use_private_key_file (o.tls_key (), asio::ssl::context::pem);
    }
    catch (const boost::system::system_error& e)
    {
      println (cerr, "error: unable to load TLS certificate and key: {}",
               e.what ());
      throw failed ();
    }

    // Load or generate the ticket key, which the authentication server
    // seals the tickets with and the gateway opens them with.
    //
    const ticket_sealer sealer (load_ticket_key (o));

    // Create the authenticator and the authentication settings. We verify
    // the Xbox Live style tokens that IW4x issues unless asked to accept
    // any token.
    //
    xbl_authenticator xa;
    development_authenticator da;
    naming_authenticator auth (o.insecure_authentication ()
                               ? static_cast<authenticator&> (da)
                               : xa);

    auth_settings as;
    for (uint32_t t: o.title ())
      as.titles.push_back (title_id {t});
    as.ticket_lifetime = chrono::seconds (o.ticket_lifetime ());
    as.sandbox         = o.sandbox ();
    as.platform        = o.platform ();

    // Create the stores, in the database if specified and in memory
    // otherwise.
    //
    unique_ptr<file_store>        files;
    unique_ptr<performance_store> values;

    if (db != nullptr)
    {
      files  = make_unique<pgsql_file_store> (*db);
      values = make_unique<pgsql_performance_store> (*db);
    }
    else
    {
      files  = make_unique<memory_file_store> ();
      values = make_unique<memory_performance_store> ();
    }

    if (verb >= 3)
      println (cerr,
               "keeping files and performance values in {}",
               db != nullptr ? format ("database {}", o.db_name ())
                             : string ("memory"));

    // Create the io_context. Note that it must outlive the servers and the
    // services (see context for details).
    //
    context ctx;

    // Publish the publisher files.
    //
    // Note that we publish them before serving so that the clients that
    // connect right away find them.
    //
    if (!pfs.empty ())
    {
      auto publish_all = [&files, &pfs] () -> asio::awaitable<void>
      {
        const timestamp now (system_clock::now ());

        for (const publisher_file& f: pfs)
        {
          const file_header h (
            co_await publish (*files, f.title, f.name, f.data, now));

          if (verb >= 3)
            println (cerr,
                     "published file {} ({} bytes) of title {} as {}",
                     f.name,
                     f.data.size (),
                     to_underlying (f.title),
                     to_underlying (h.id));
        }
      };

      // Run the publishing to completion, which also waits for the database
      // operations (see pgsql_database).
      //
      exception_ptr ep;
      asio::co_spawn (ctx, publish_all (), [&ep] (exception_ptr e)
      {
        ep = move (e);
      });

      ctx.run ();
      ctx.restart ();

      if (ep != nullptr)
      {
        try
        {
          rethrow_exception (ep);
        }
        catch (const std::exception& e)
        {
          println (cerr, "error: unable to publish files: {}", e.what ());
          throw failed ();
        }
      }

      if (verb >= 2)
        println (cerr, "published {} publisher file(s)", pfs.size ());
    }

    // Create the gateway services.
    //
    lsg_registry registry;

    optional<bandwidth_service> bandwidth;
    try
    {
      bandwidth.emplace (ctx.get_executor (), be, move (bs));
    }
    catch (const boost::system::system_error& e)
    {
      println (cerr, "error: unable to bind bandwidth test socket: {}",
               e.what ());
      throw failed ();
    }

    matchmaking_service matchmaking;
    messaging_service   messaging (registry,
                                   [&auth] (user_id u) {return auth.name (u);});
    storage_service     storage (*files);
    performance_service performance (*values);

    const service_map services
    {
      {5,  matchmaking},
      {6,  messaging},
      {10, storage},
      {17, performance},
      {18, *bandwidth}
    };

    // Start the servers.
    //
    optional<auth_server> a;
    optional<lsg_server>  g;
    try
    {
      a.emplace (ctx.get_executor (), ae, tls, auth, sealer, move (as));
      g.emplace (ctx.get_executor (),
                 ge,
                 sealer,
                 services,
                 registry,
                 lsg_settings ());
    }
    catch (const boost::system::system_error& e)
    {
      println (cerr, "error: unable to listen: {}", e.what ());
      throw failed ();
    }

    if (o.insecure_authentication () && verb >= 1)
      println (cerr,
               "warning: accepting any platform token (insecure "
               "authentication)");

    if (verb >= 2)
      println (cerr,
               "listening on {} and {}, testing bandwidth on {}",
               to_string (a->endpoint ()),
               to_string (g->endpoint ()),
               to_string (bandwidth->endpoint ()));

    // Flush so that whoever reads the endpoints gets them right away.
    //
    if (o.print_endpoints ())
    {
      println ("{}\n{}\n{}",
               to_string (a->endpoint ()),
               to_string (g->endpoint ()),
               to_string (bandwidth->endpoint ()));
      fflush (stdout);
    }

    // Serve until either server fails or a termination signal arrives.
    //
    int r (0);
    {
      // Return the completion handler of the server's coroutine that stops
      // the io_context if the server fails.
      //
      auto stop = [&ctx, &r] (const char* what)
      {
        return [&ctx, &r, what] (exception_ptr e)
        {
          if (e == nullptr)
            return;

          try
          {
            rethrow_exception (e);
          }
          catch (const std::exception& x)
          {
            println (cerr, "error: {} server failed: {}", what, x.what ());
          }

          r = 1;
          ctx.stop ();
        };
      };

      asio::co_spawn (ctx, a->run (), stop ("authentication"));
      asio::co_spawn (ctx, g->run (), stop ("gateway"));
      asio::co_spawn (ctx, bandwidth->run (), stop ("bandwidth test"));

      asio::signal_set ss (ctx, SIGINT, SIGTERM);
      ss.async_wait ([&ctx] (const boost::system::error_code& ec, int)
      {
        if (ec)
          return;

        if (verb >= 2)
          println (cerr, "shutting down");

        ctx.stop ();
      });

      ctx.run ();
    }

    // Shut down.
    //
    // First wait for the database operations in progress since their
    // completions are posted to the io_context. Then destroy the pending
    // handlers and with them the coroutines of the connections that are
    // still open. Note that their destruction calls back into the servers
    // and services (see lsg_server), so the handlers must go before them.
    //
    if (db != nullptr)
      db->join ();

    ctx.shutdown ();

    return r;
  }
  catch (const failed&)
  {
    return 1; // Diagnostics already issued.
  }
  catch (const cli::exception& e)
  {
    ostringstream os;
    os << e;

    println (cerr,
             "error: {}\n"
             "  info: run 'obe --help' for more information",
             os.str ());
    return 1;
  }
}

int
main (int argc, char* argv[])
{
  return obe::main (argc, argv);
}
