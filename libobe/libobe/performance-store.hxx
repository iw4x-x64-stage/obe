// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <map>
#include <tuple>

#include <boost/asio/awaitable.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>

#include <libobe/export.hxx>

namespace obe
{
  using boost::asio::awaitable;

  // The user's performance value (bdPerformanceValue):
  //
  // uint64  user id
  // int64   value
  //
  struct LIBOBE_SYMEXPORT performance_value
  {
    user_id user {};
    int64_t value = 0;

    performance_value () = default;

    performance_value (user_id u, int64_t v): user (u), value (v) {}

    // Throw bit_parsing on failure.
    //
    explicit
    performance_value (bit_parser&);

    void
    serialize (bit_serializer&) const;
  };

  // The performance value storage (for the performance service).
  //
  // The store keeps a value per title, kind, and user. Like file_store, the
  // operations are atomic coroutines that run on the caller's executor and
  // throw task_error on failure (see file_store for details).
  //
  class LIBOBE_SYMEXPORT performance_store
  {
  public:
    // Store the values of the kind, replacing the existing ones.
    //
    virtual awaitable<void>
    submit (title_id, uint32_t kind, vector<performance_value>) = 0;

    // Return the values of the kind of those users that have one, in the
    // order of the user ids.
    //
    virtual awaitable<vector<performance_value>>
    query (title_id, uint32_t kind, vector<user_id>) = 0;

    performance_store () = default;

    virtual
    ~performance_store ();

    performance_store (const performance_store&) = delete;
    performance_store& operator= (const performance_store&) = delete;
  };

  // The performance store that keeps the values in memory, for development
  // and testing.
  //
  class LIBOBE_SYMEXPORT memory_performance_store: public performance_store
  {
  public:
    virtual awaitable<void>
    submit (title_id, uint32_t, vector<performance_value>) override;

    virtual awaitable<vector<performance_value>>
    query (title_id, uint32_t, vector<user_id>) override;

  private:
    using key = std::tuple<title_id, uint32_t, user_id>; // Title, kind, user.

    std::map<key, int64_t> values_;
  };
}
