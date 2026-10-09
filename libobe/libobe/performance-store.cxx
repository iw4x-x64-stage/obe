// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/performance-store.hxx>

using namespace std;

namespace obe
{
  // performance_value
  //
  performance_value::
  performance_value (bit_parser& p)
    : user (user_id {p.next_uint64 ()}),
      value (p.next_int64 ())
  {
  }

  void performance_value::
  serialize (bit_serializer& s) const
  {
    s.next_uint64 (to_underlying (user));
    s.next_int64 (value);
  }

  // performance_store
  //
  performance_store::
  ~performance_store ()
  {
  }

  // memory_performance_store
  //
  awaitable<void> memory_performance_store::
  submit (title_id t, uint32_t k, vector<performance_value> vs)
  {
    for (const performance_value& v: vs)
      values_[key (t, k, v.user)] = v.value;

    co_return;
  }

  awaitable<vector<performance_value>> memory_performance_store::
  query (title_id t, uint32_t k, vector<user_id> us)
  {
    vector<performance_value> r;
    for (user_id u: us)
    {
      auto i (values_.find (key (t, k, u)));
      if (i != values_.end ())
        r.emplace_back (u, i->second);
    }

    co_return r;
  }
}
