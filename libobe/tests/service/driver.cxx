// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <map>
#include <print>
#include <string>
#include <vector>
#include <format>
#include <cstdint>
#include <sstream>
#include <random>
#include <iostream>
#include <exception> // exception_ptr, rethrow_exception()
#include <stdexcept> // invalid_argument

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <odb/pgsql/database.hxx>
#include <odb/pgsql/connection.hxx>

#include <libobe/pgsql.hxx>
#include <libobe/service.hxx>
#include <libobe/file-store.hxx>
#include <libobe/bit-parser.hxx>
#include <libobe/lsg-registry.hxx>
#include <libobe/bit-serializer.hxx>
#include <libobe/service-storage.hxx>
#include <libobe/service-messaging.hxx>
#include <libobe/service-matchmaking.hxx>
#include <libobe/service-performance.hxx>
#include <libobe/performance-store.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

namespace asio = boost::asio;

static const title_id title {1234};

// The test database, created in the PostgreSQL server of the maintenance
// database on construction and dropped on destruction.
//
// Note that we use the libpq defaults for everything else (the user, the
// host, etc) and that the database is dropped even if it is still in use
// (by the pool connections of a failed test).
//
class test_database
{
public:
  explicit
  test_database (string maintenance)
    : admin_ ("", "", move (maintenance))
  {
    random_device rd;
    name_ = format ("obe_test_{:08x}{:08x}", rd (), rd ());

    admin_.connection ()->execute ("CREATE DATABASE " + name_);
  }

  ~test_database ()
  {
    try
    {
      admin_.connection ()->execute (
        "DROP DATABASE " + name_ + " WITH (FORCE)");
    }
    catch (const std::exception& e)
    {
      println (cerr,
               "warning: unable to drop database {}: {}",
               name_, e.what ());
    }
  }

  const string&
  name () const noexcept {return name_;}

  test_database (const test_database&) = delete;
  test_database& operator= (const test_database&) = delete;

private:
  odb::pgsql::database admin_;
  string               name_;
};

static bytes
parse_hex (const string& s)
{
  if (s.size () % 2 != 0)
    throw invalid_argument ("odd number of hex digits");

  bytes r;
  for (size_t i (0); i != s.size (); i += 2)
  {
    size_t n;
    const unsigned long v (stoul (s.substr (i, 2), &n, 16));

    if (n != 2)
      throw invalid_argument ("invalid hex digit");

    r.push_back (static_cast<uint8_t> (v));
  }
  return r;
}

static string
to_hex (span<const uint8_t> d)
{
  string r;
  for (uint8_t b: d)
    r += format ("{:02x}", b);
  return r;
}

// Return the blob data: either hex or '^<n>', the n-th blob received so
// far.
//
static bytes
blob_data (const string& s, const vector<bytes>& blobs)
{
  if (s.starts_with ('^'))
  {
    const size_t i (stoul (s.substr (1)));

    if (i >= blobs.size ())
      throw invalid_argument ("no blob " + s);

    return blobs[i];
  }

  return parse_hex (s);
}

// Serialize the value line (see main()).
//
static void
serialize (bit_serializer& s, const string& l, const vector<bytes>& blobs)
{
  istringstream is (l);
  string t, v;
  is >> t;
  getline (is >> ws, v);

  if      (t == "bool")   s.next_bool (v == "true");
  else if (t == "uint8")  s.next_uint8 (static_cast<uint8_t> (stoul (v)));
  else if (t == "uint16") s.next_uint16 (static_cast<uint16_t> (stoul (v)));
  else if (t == "int32")  s.next_int32 (static_cast<int32_t> (stol (v)));
  else if (t == "uint32") s.next_uint32 (static_cast<uint32_t> (stoul (v)));
  else if (t == "int64")  s.next_int64 (stoll (v));
  else if (t == "uint64") s.next_uint64 (stoull (v));
  else if (t == "string") s.next_string (v);
  else if (t == "blob")   s.next_blob (blob_data (v, blobs));
  else if (t == "bytes")  s.next_bytes (parse_hex (v));
  else
    throw invalid_argument ("unknown type '" + t + "'");
}

// Print the values of the buffer as value lines, prefixed with the
// specified string, and save the blobs.
//
static void
print (span<const uint8_t> d, const string& prefix, vector<bytes>& blobs)
{
  bit_parser p (d, "reply");

  for (optional<bit_type> t; (t = p.peek ()) && *t != bit_type::none; )
  {
    string v;
    switch (*t)
    {
      case bit_type::boolean: v = p.next_bool () ? "true" : "false";    break;
      case bit_type::uchar8:  v = format ("{}", p.next_uint8 ());       break;
      case bit_type::uint16:  v = format ("{}", p.next_uint16 ());      break;
      case bit_type::int32:   v = format ("{}", p.next_int32 ());       break;
      case bit_type::uint32:  v = format ("{}", p.next_uint32 ());      break;
      case bit_type::int64:   v = format ("{}", p.next_int64 ());       break;
      case bit_type::uint64:  v = format ("{}", p.next_uint64 ());      break;
      case bit_type::string:  v = p.next_string (p.remaining () / 8);   break;
      case bit_type::blob:
      {
        blobs.push_back (p.next_blob (p.remaining () / 8));
        v = to_hex (blobs.back ());
        break;
      }
      default:
        throw invalid_argument (format ("unexpected {} in reply", *t));
    }

    const char* n (*t == bit_type::boolean ? "bool"  :
                   *t == bit_type::uchar8  ? "uint8" : to_string (*t));

    println ("{}{} {}", prefix, n, v);
  }
}

// Usage: argv[0] [--pgsql <database>] <service>
//
// Create the service (matchmaking, messaging, storage, or performance) for
// title 1234 and run the tasks read from stdin against it.
// The stores are kept in memory or, with --pgsql, in a new PostgreSQL
// database created in the server of the specified maintenance database
// (and dropped on exit).
// The service limits are lowered: matchmaking hosts 1 session per
// connection, messaging sends to 2 recipients, storage keeps 1 file of up to
// 4 bytes per user, and performance takes 2 values.
// Each task starts with the header line:
//
// task <user> <connection> <operation>
//
// Followed by the parameters as value lines, one per value:
//
// bool <true|false>
// uint8|uint16|int32|uint32|int64|uint64 <decimal>
// string <characters>      (the rest of the line)
// blob <hex>|^<n>          (^<n> is the n-th blob received, from 0)
// bytes <hex>              (raw bytes, no tag)
//
// The task ends with an empty line or the end of the input.
//
// Print the reply as 'ok' followed by the results in the same format or
// 'error <code>: <description>'. The
// connections are attached to the registry on their first task and the
// messages pushed to them are printed as 'push <connection>' followed by the
// values, each line indented.
//
// The line 'disconnect <user> <connection>' detaches the connection and
// notifies the service.
//
int
main (int argc, char* argv[])
{
  optional<string> pgsql;
  int i (1);

  if (argc == 4 && string (argv[1]) == "--pgsql")
  {
    pgsql = argv[2];
    i = 3;
  }

  if (i != argc - 1)
  {
    println (cerr, "usage: {} [--pgsql <database>] <service>", argv[0]);
    return 1;
  }

  const string n (argv[i]);

  // Create the stores.
  //
  // Note that the order of the declarations matters: the database must
  // outlive the stores and the test database the database.
  //
  optional<test_database> tdb;
  unique_ptr<pgsql_database> db;
  unique_ptr<file_store> files;
  unique_ptr<performance_store> values;

  try
  {
    if (pgsql)
    {
      tdb.emplace (*pgsql);

      pgsql_settings s;
      s.name = tdb->name ();
      s.max_connections = 2;

      db = make_unique<pgsql_database> (s);
      db->migrate ();

      files = make_unique<pgsql_file_store> (*db);
      values = make_unique<pgsql_performance_store> (*db);
    }
    else
    {
      files = make_unique<memory_file_store> ();
      values = make_unique<memory_performance_store> ();
    }
  }
  catch (const std::exception& e)
  {
    println (cerr, "error: unable to create stores: {}", e.what ());
    return 1;
  }

  lsg_registry registry;

  // Note that the limits are lowered to make them easy to test.
  //
  unique_ptr<service> svc;
  if (n == "matchmaking")
  {
    matchmaking_settings s;
    s.max_hosted = 1;
    svc = make_unique<matchmaking_service> (s);
  }
  else if (n == "messaging")
  {
    messaging_settings s;
    s.max_recipients = 2;
    svc = make_unique<messaging_service> (
      registry,
      [] (user_id u) {return format ("user-{}", to_underlying (u));},
      s);
  }
  else if (n == "storage")
  {
    storage_settings s;
    s.max_file_size = 4;
    s.max_files = 1;
    svc = make_unique<storage_service> (*files, s);
  }
  else if (n == "performance")
  {
    performance_settings s;
    s.max_values = 2;
    svc = make_unique<performance_service> (*values, s);
  }
  else
  {
    println (cerr, "error: unknown service '{}'", n);
    return 1;
  }

  map<uint64_t, lsg_registry::registration> registrations;
  vector<bytes> blobs; // Received so far.

  // Run the handler to completion, rethrowing its exception, if any.
  //
  // Note that we rethrow once the io_context is done rather than from the
  // completion handler: an exception that escapes run() leaves the
  // coroutine machinery in the middle of the completion.
  //
  asio::io_context ctx;

  auto await = [&ctx] (awaitable<void> a)
  {
    exception_ptr r;
    asio::co_spawn (ctx, move (a), [&r] (exception_ptr e) {r = move (e);});

    ctx.run ();
    ctx.restart ();

    if (r)
      rethrow_exception (r);
  };

  // Run the task.
  //
  auto run = [&svc, &registry, &registrations, &blobs, &await]
             (const lsg_identity& id, uint8_t op, const vector<string>& ls)
  {
    // Attach the connection if this is its first task.
    //
    if (!registrations.contains (id.connection))
    {
      auto push = [c = id.connection] (const bytes& p)
      {
        println ("push {}", c);

        vector<bytes> bs;
        print (p, "  ", bs);
        return true;
      };

      registrations.emplace (id.connection, registry.attach (id, push));
    }

    // Serialize the parameters.
    //
    bytes in;
    {
      bit_serializer s (in);
      for (const string& l: ls)
        serialize (s, l, blobs);

      s.next_type (bit_type::none);
    }

    // Handle the task.
    //
    bytes out;
    try
    {
      bit_parser p (in, "task");
      bit_serializer s (out);
      await (svc->handle (id, op, p, s));
    }
    catch (const task_error& e)
    {
      println ("error {}: {}", to_underlying (e.code), e.what ());
      return;
    }
    catch (const bit_parsing& e)
    {
      println ("error {}: {}",
               to_underlying (lsg_error::parameter_parse_error),
               e.description);
      return;
    }

    // Print the reply.
    //
    println ("ok");
    print (out, "", blobs);
  };

  try
  {
    optional<lsg_identity> id;
    uint8_t op (0);
    vector<string> ls;

    auto flush = [&id, &op, &ls, &run] ()
    {
      if (id)
        run (*id, op, ls);

      id = nullopt;
      ls.clear ();
    };

    for (string l; getline (cin, l); )
    {
      istringstream is (l);
      string k;
      is >> k;

      if (k == "task" || k == "disconnect")
      {
        flush ();

        uint64_t u, c;
        is >> u >> c;

        const lsg_identity i {user_id {u}, title, license_id {0}, c, {}};

        if (k == "task")
        {
          unsigned int o;
          is >> o;
          op = static_cast<uint8_t> (o);
          id = i;
        }
        else
        {
          registrations.erase (c);
          svc->disconnect (i);
        }

        if (is.fail ())
          throw invalid_argument ("invalid line '" + l + "'");
      }
      else if (l.empty ())
        flush ();
      else
        ls.push_back (move (l));
    }

    flush ();
  }
  catch (const invalid_argument& e)
  {
    println (cerr, "error: {}", e.what ());
    return 1;
  }
}
