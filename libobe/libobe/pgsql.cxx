// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/pgsql.hxx>

#include <map>
#include <thread>      // this_thread::sleep_for()
#include <concepts>    // invocable, same_as
#include <type_traits> // invoke_result_t, is_void_v

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <odb/database.hxx>
#include <odb/exceptions.hxx>
#include <odb/transaction.hxx>
#include <odb/schema-catalog.hxx>

#include <odb/pgsql/database.hxx>
#include <odb/pgsql/connection-factory.hxx>

#include <libobe/model.hxx>
#include <libobe/model-odb.hxx>

#include <libobe/service.hxx> // task_error

using namespace std;

namespace obe
{
  namespace asio = boost::asio;

  // The advisory lock key that serializes the schema migrations (the ASCII
  // codes of "obe").
  //
  static const int64_t migration_lock (0x6f6265);

  // Return the description of the database error. Note that the libpq
  // messages end with a newline, which we strip.
  //
  static string
  describe (const odb::exception& e)
  {
    string r (e.what ());

    while (!r.empty () && (r.back () == '\n' || r.back () == ' '))
      r.pop_back ();

    return r;
  }

  // Execute the SQL statement formatted from the arguments on the connection
  // and return the number of affected rows.
  //
  // Note that the arguments are formatted into the statement verbatim (they
  // are not quoted or escaped) and so should never come from the external
  // input. Such values are passed with ODB queries instead.
  //
  template <typename... A>
    requires formattable_arguments<A...>
  static unsigned long long
  execute (odb::pgsql::connection& c, std::format_string<A...> f, A&&... a)
  {
    return c.execute (std::format (f, std::forward<A> (a)...));
  }

  // pgsql_database
  //
  struct pgsql_database::transaction_pool
  {
    odb::pgsql::database database;
    asio::thread_pool    pool;
    size_t               retry;

    explicit
    transaction_pool (const pgsql_settings& s)
      : database (s.user,
                  s.password,
                  s.name,
                  s.host,
                  s.port,
                  "options='-c default_transaction_isolation=serializable'",
                  make_unique<odb::pgsql::connection_pool_factory> (
                    s.max_connections)),
        pool (s.max_connections),
        retry (s.retry)
    {
    }

    // Perform the operation in a transaction on a pool thread and return
    // its result. Retry the operation on recoverable errors (so it should
    // only change the database) and translate the database errors to
    // task_error.
    //
    // Note that the operation is called on the pool thread and so should not
    // touch the caller's state other than by its (copied) captures.
    //
    template <typename F>
      requires std::invocable<const F&, odb::database&> &&
               (!std::is_void_v<std::invoke_result_t<const F&,
                                                     odb::database&>>)
    awaitable<std::invoke_result_t<const F&, odb::database&>>
    execute (F f)
    {
      using result = std::invoke_result_t<const F&, odb::database&>;

      auto run = [this, f = move (f)] () -> awaitable<result>
      {
        co_return perform (f);
      };

      // Note that the completion resumes us on our executor.
      //
      co_return co_await asio::co_spawn (pool, move (run), asio::use_awaitable);
    }

    template <typename F>
    std::invoke_result_t<const F&, odb::database&>
    perform (const F& f)
    {
      for (size_t i (0);; ++i)
      {
        try
        {
          odb::transaction t (database.begin ());
          auto r (f (database));
          t.commit ();
          return r;
        }
        catch (const odb::recoverable& e)
        {
          if (i == retry)
            throw task_error (lsg_error::service_not_available,
                              "database error: {} (after {} retries)",
                              describe (e), retry);

          // Back off before retrying since the cause (a lost connection, a
          // concurrent update) may take a moment to go away.
          //
          this_thread::sleep_for (
            chrono::milliseconds (10 << min<size_t> (i, 6)));
        }
        catch (const odb::exception& e)
        {
          throw task_error (lsg_error::service_not_available,
                            "database error: {}",
                            describe (e));
        }
      }
    }
  };

  pgsql_database::
  pgsql_database (const pgsql_settings& s)
    : transactions_ (make_unique<transaction_pool> (s))
  {
    LIBOBE_PRE (s.max_connections != 0);
  }

  pgsql_database::
  ~pgsql_database ()
  {
    // Note that the pool must be joined before the database is destroyed
    // (which happens after this destructor's body).
    //
    join ();
  }

  void pgsql_database::
  join ()
  {
    // Note that the operations already handed over to the pool are
    // performed (rather than abandoned) and that joining the pool repeatedly
    // is a noop.
    //
    transactions_->pool.join ();
  }

  uint64_t pgsql_database::
  schema_version ()
  try
  {
    return transactions_->database.schema_version ();
  }
  catch (const odb::exception& e)
  {
    throw database_error ("database error: {}", describe (e));
  }

  uint64_t pgsql_database::
  current_schema_version () const
  {
    return odb::schema_catalog::current_version (
      transactions_->database);
  }

  uint64_t pgsql_database::
  migrate ()
  try
  {
    odb::pgsql::database& db (transactions_->database);

    // Serialize the concurrent migrations.
    //
    // We hold the session lock on a dedicated connection and start the
    // transaction only once we have it. Note that taking the lock inside
    // the (serializable) transaction would not do: its snapshot would
    // predate the migration we waited for.
    //
    odb::pgsql::connection_ptr c (db.connection ());
    execute (*c, "SELECT pg_advisory_lock ({})", migration_lock);

    struct unlock
    {
      odb::pgsql::connection& c;

      ~unlock ()
      {
        // If this fails, then the connection is likely broken, in which
        // case the server releases the lock when the session ends.
        //
        try
        {
          execute (c, "SELECT pg_advisory_unlock ({})", migration_lock);
        }
        catch (const odb::exception&)
        {
        }
      }
    } u {*c};

    // Note that reading the schema version inside the transaction is safe
    // (the ODB runtime checks that the version table exists first).
    //
    odb::transaction t (c->begin ());

    const uint64_t v (db.schema_version ());
    const uint64_t cv (odb::schema_catalog::current_version (db));

    if (v != 0)
    {
      if (v < odb::schema_catalog::base_version (db))
        throw database_error (
          "database schema version {} is too old to migrate", v);

      if (v > cv)
        throw database_error (
          "database schema version {} is newer than {}", v, cv);
    }

    if (v == 0)
      odb::schema_catalog::create_schema (db, "", false /* drop */);
    else if (v != cv)
      odb::schema_catalog::migrate (db);

    t.commit ();
    return v;
  }
  catch (const odb::exception& e)
  {
    throw database_error ("database error: {}", describe (e));
  }

  // Return the file header of the file record or its header view.
  //
  template <typename R>
    requires std::same_as<R, file_record> ||
             std::same_as<R, file_record_header>
  static file_header
  to_header (const R& r)
  {
    file_header h;
    h.id = r.id;
    h.created = r.created;
    h.modified = r.modified;
    h.flags = {r.flag1, r.flag2};
    h.owner = r.owner;
    h.name = r.name;
    h.size = r.size;
    return h;
  }

  // pgsql_file_store
  //
  pgsql_file_store::
  pgsql_file_store (pgsql_database& d)
    : database_ (d)
  {
  }

  awaitable<optional<stored_file>> pgsql_file_store::
  find (title_id t, file_id i)
  {
    co_return co_await database_.transactions_->execute (
      [t, i] (odb::database& db) -> optional<stored_file>
    {
      unique_ptr<file_record> r (db.find<file_record> (i));

      if (r == nullptr || r->title != t)
        return nullopt;

      return stored_file {to_header (*r), move (r->data)};
    });
  }

  awaitable<vector<file_header>> pgsql_file_store::
  list (title_id t,
        optional<user_id> o,
        timestamp since,
        string prefix,
        size_t limit)
  {
    co_return co_await database_.transactions_->execute (
      [t, o, since, prefix = move (prefix), limit] (odb::database& db)
    {
      using query = odb::query<file_record_header>;

      query q (query::title == t &&
               query::modified >= since);

      if (o)
        q = q && query::owner == *o;

      if (!prefix.empty ())
        q = q && "starts_with(" + query::name + "," +
                 query::_val (prefix) + ")";

      q += "ORDER BY" + query::id +
           "LIMIT" + query::_val (static_cast<uint64_t> (limit));

      vector<file_header> r;
      for (const file_record_header& h: db.query<file_record_header> (q))
        r.push_back (to_header (h));

      return r;
    });
  }

  awaitable<optional<file_header>> pgsql_file_store::
  upload (title_id t,
          user_id o,
          string n,
          array<bool, 2> fs,
          bytes d,
          timestamp now,
          size_t limit)
  {
    LIBOBE_PRE (!n.empty () && n.size () <= file_header::max_name);

    co_return co_await database_.transactions_->execute (
      [t, o, n = move (n), fs, d = move (d), now, limit] (odb::database& db)
      -> optional<file_header>
    {
      using query = odb::query<file_record>;

      const query q (query::title == t &&
                     query::owner == o);

      unique_ptr<file_record> r (
        db.query_one<file_record> (q && query::name == n));

      // Note that the data is copied rather than moved since the
      // operation may be retried.
      //
      const bool existing (r != nullptr);

      if (!existing)
      {
        using count_query = odb::query<file_record_count>;

        const file_record_count c (
          db.query_value<file_record_count> (
            count_query::title == t &&
            count_query::owner == o));

        if (c.result >= limit)
          return nullopt;

        r.reset (new file_record ());
        r->title = t;
        r->owner = o;
        r->name = n;
        r->created = now;
      }

      r->flag1 = fs[0];
      r->flag2 = fs[1];
      r->modified = now;
      r->size = static_cast<uint32_t> (d.size ());
      r->data = d;

      if (existing)
        db.update (*r);
      else
        db.persist (*r); // Assigns the id.

      return to_header (*r);
    });
  }

  awaitable<optional<file_header>> pgsql_file_store::
  update (title_id t, file_id i, bytes d, timestamp now)
  {
    co_return co_await database_.transactions_->execute (
      [t, i, d = move (d), now] (odb::database& db) -> optional<file_header>
    {
      unique_ptr<file_record> r (db.find<file_record> (i));

      if (r == nullptr || r->title != t)
        return nullopt;

      r->modified = now;
      r->size = static_cast<uint32_t> (d.size ());
      r->data = d;

      db.update (*r);
      return to_header (*r);
    });
  }

  // pgsql_performance_store
  //
  pgsql_performance_store::
  pgsql_performance_store (pgsql_database& d)
    : database_ (d)
  {
  }

  awaitable<void> pgsql_performance_store::
  submit (title_id t, uint32_t k, vector<performance_value> vs)
  {
    // Note that the result is just to have one (see execute()).
    //
    co_await database_.transactions_->execute (
      [t, k, vs = move (vs)] (odb::database& db)
    {
      for (const performance_value& v: vs)
      {
        const performance_key id {t, k, v.user};

        if (unique_ptr<performance_record> r =
              db.find<performance_record> (id))
        {
          r->value = v.value;
          db.update (*r);
        }
        else
          db.persist (performance_record {id, v.value});
      }

      return vs.size ();
    });
  }

  awaitable<vector<performance_value>> pgsql_performance_store::
  query (title_id t, uint32_t k, vector<user_id> us)
  {
    if (us.empty ())
      co_return vector<performance_value> ();

    co_return co_await database_.transactions_->execute (
      [t, k, us = move (us)] (odb::database& db)
    {
      using query = odb::query<performance_record>;

      map<user_id, int64_t> vs;
      for (const performance_record& r:
             db.query<performance_record> (
               query::id.title == t &&
               query::id.kind == k  &&
               query::id.user.in_range (us.begin (), us.end ())))
        vs.emplace (r.id.user, r.value);

      // Return the values in the order of the user ids.
      //
      vector<performance_value> r;
      for (user_id u: us)
      {
        if (auto i = vs.find (u); i != vs.end ())
          r.emplace_back (u, i->second);
      }

      return r;
    });
  }
}
