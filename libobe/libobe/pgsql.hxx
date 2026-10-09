// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <boost/asio/awaitable.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/file-store.hxx>
#include <libobe/performance-store.hxx>

#include <libobe/export.hxx>

namespace obe
{
  using boost::asio::awaitable;

  // The database failure (the database is unavailable, its schema cannot
  // be migrated, etc). The description is formatted from the arguments, for
  // example:
  //
  // throw database_error ("database schema version {} is too old", v);
  //
  class database_error: public runtime_error
  {
  public:
    template <typename... A>
      requires formattable_arguments<A...>
    explicit
    database_error (std::format_string<A...> f, A&&... a)
      : runtime_error (std::format (f, std::forward<A> (a)...)) {}
  };

  // The PostgreSQL database connection parameters. The empty values (and
  // zero port) select the libpq defaults (see the PostgreSQL documentation
  // on connection parameters), for example, the local UNIX-domain socket
  // with the user name of the process.
  //
  struct pgsql_settings
  {
    string   user;
    string   password;
    string   name;
    string   host;
    uint16_t port = 0;

    // The most concurrent connections, which is also the number of threads
    // that perform the database operations.
    //
    size_t max_connections = 5;

    // The number of times an operation is retried if it fails with a
    // recoverable error (for example, a serialization failure due to a
    // concurrent update or a lost connection).
    //
    size_t retry = 10;
  };

  // The PostgreSQL database of the stores.
  //
  // The database operations are blocking, so they are performed by a pool of
  // threads, each using its own connection. The stores' coroutines hand the
  // operation over to the pool and are resumed on their executor once it is
  // done. Every operation runs in a serializable transaction (so they are
  // atomic and isolated whichever the process or thread performing them),
  // which is retried on recoverable errors.
  //
  // The database schema is created and migrated explicitly (see migrate())
  // rather than on startup since several processes may share the database.
  //
  class LIBOBE_SYMEXPORT pgsql_database
  {
  public:
    // Note that no connection is established until the first operation.
    //
    explicit
    pgsql_database (const pgsql_settings&);

    // Wait for the operations in progress to complete (see join()).
    //
    ~pgsql_database ();

    // Wait for the operations in progress to complete. No further operations
    // can be performed after this call.
    //
    // Note that an operation's completion is posted to the executor of the
    // coroutine that awaits it, so this function must be called before that
    // executor's io_context is destroyed (normally, once it is stopped).
    //
    void
    join ();

    pgsql_database (const pgsql_database&) = delete;
    pgsql_database& operator= (const pgsql_database&) = delete;

    // Return the version of the database schema or 0 if there is no schema.
    //
    // Throw database_error if the database is unavailable.
    //
    uint64_t
    schema_version ();

    // Return the schema version this library uses.
    //
    uint64_t
    current_schema_version () const;

    // Create the database schema if there is none or migrate it to the
    // current version. Return the version it was at (0 if there was no
    // schema). The concurrent migrations are serialized.
    //
    // Throw database_error if the database is unavailable or if its schema is
    // older than the base version (and so cannot be migrated) or newer than
    // the current version.
    //
    uint64_t
    migrate ();

  private:
    friend class pgsql_file_store;
    friend class pgsql_performance_store;

    // The ODB database and the threads that perform the operations, each in
    // its own transaction (see pgsql.cxx).
    //
    struct transaction_pool;
    unique_ptr<transaction_pool> transactions_;
  };

  // The file store in the PostgreSQL database. The database should outlive
  // the store.
  //
  class LIBOBE_SYMEXPORT pgsql_file_store: public file_store
  {
  public:
    explicit
    pgsql_file_store (pgsql_database&);

    virtual awaitable<optional<stored_file>>
    find (title_id, file_id) override;

    virtual awaitable<vector<file_header>>
    list (title_id,
          optional<user_id>,
          timestamp,
          string,
          size_t) override;

    virtual awaitable<optional<file_header>>
    upload (title_id,
            user_id,
            string,
            array<bool, 2>,
            bytes,
            timestamp,
            size_t) override;

    virtual awaitable<optional<file_header>>
    update (title_id, file_id, bytes, timestamp) override;

  private:
    pgsql_database& database_;
  };

  // The performance store in the PostgreSQL database. The database should
  // outlive the store.
  //
  class LIBOBE_SYMEXPORT pgsql_performance_store: public performance_store
  {
  public:
    explicit
    pgsql_performance_store (pgsql_database&);

    virtual awaitable<void>
    submit (title_id, uint32_t, vector<performance_value>) override;

    virtual awaitable<vector<performance_value>>
    query (title_id, uint32_t, vector<user_id>) override;

  private:
    pgsql_database& database_;
  };
}
