// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <print>
#include <string>
#include <format>
#include <random>
#include <concepts>  // convertible_to
#include <utility>   // move(), forward()
#include <iostream>
#include <exception>

#include <odb/database.hxx>
#include <odb/transaction.hxx>

#include <odb/pgsql/database.hxx>

#include <libobe/pgsql.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

// The ODB database or connection that executes the SQL statements.
//
template <typename T>
concept statement_executor = requires (T& x, const string& s)
{
  {x.execute (s)} -> convertible_to<unsigned long long>;
};

// Execute the SQL statement formatted from the arguments and return the
// number of rows it affected or, for SELECT, produced.
//
// Note that the arguments are formatted into the statement verbatim (they
// are not quoted or escaped), which is fine for the values we control.
//
template <statement_executor E, typename... A>
  requires formattable_arguments<A...>
static unsigned long long
execute (E& e, format_string<A...> f, A&&... a)
{
  return e.execute (format (f, forward<A> (a)...));
}

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

    execute (*admin_.connection (), "CREATE DATABASE {}", name_);
  }

  ~test_database ()
  {
    try
    {
      execute (*admin_.connection (), "DROP DATABASE {} WITH (FORCE)", name_);
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

// Usage: argv[0] <database>
//
// Create a new PostgreSQL database in the server of the specified
// maintenance database, migrate it twice (which must create the schema and
// then find it current), and print, one per line, the versions migrated
// from, the number of tables and schema version records, and the number of
// our version records and tables:
//
// migrated <version>
// tables <count>
// versions <count>
// version obe <count>
// table <name> <count>
//
// Then raise the schema version by one and print the version the database
// reports and the error migrating it fails with:
//
// schema version <version>
// refused: <error>
//
int
main (int argc, char* argv[])
try
{
  if (argc != 2)
  {
    println (cerr, "usage: {} <database>", argv[0]);
    return 1;
  }

  test_database tdb (argv[1]);

  {
    pgsql_settings s;
    s.name = tdb.name ();
    s.max_connections = 1;

    pgsql_database db (s);

    println ("migrated {}", db.migrate ());
    println ("migrated {}", db.migrate ());

    assert (db.schema_version () == db.current_schema_version ());
  }

  // Inspect the result over a connection of our own.
  //
  // Note that execute() returns the number of rows a SELECT produces,
  // which is all we need to check the catalog.
  //
  {
    odb::pgsql::database db ("", "", tdb.name ());
    odb::transaction t (db.begin ());

    println ("tables {}",
             execute (db,
                      "SELECT 1 FROM pg_tables WHERE schemaname = 'public'"));

    println ("versions {}", execute (db, "SELECT 1 FROM schema_version"));

    // Note that our schema is the default one, which has the empty name.
    //
    println ("version obe {}",
             execute (db,
                      "SELECT 1 FROM schema_version WHERE name = ''"));

    for (const char* n: {"file", "performance", "schema_version"})
      println ("table {} {}",
               n,
               execute (db,
                        "SELECT 1 FROM pg_tables "
                        "WHERE schemaname = 'public' AND tablename = '{}'",
                        n));

    t.commit ();
  }

  // Raise the schema version past the current one and make sure the
  // database is then refused.
  //
  {
    odb::pgsql::database db ("", "", tdb.name ());
    odb::transaction t (db.begin ());
    execute (db,
             "UPDATE schema_version SET version = version + 1 "
             "WHERE name = ''");
    t.commit ();
  }

  {
    pgsql_settings s;
    s.name = tdb.name ();
    s.max_connections = 1;

    pgsql_database db (s);

    println ("schema version {}", db.schema_version ());

    try
    {
      db.migrate ();
      assert (false);
    }
    catch (const database_error& e)
    {
      println ("refused: {}", e.what ());
    }
  }
}
catch (const std::exception& e)
{
  println (cerr, "error: {}", e.what ());
  return 1;
}
