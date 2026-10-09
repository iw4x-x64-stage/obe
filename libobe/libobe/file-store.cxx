// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/file-store.hxx>

#include <limits> // numeric_limits

using namespace std;

namespace obe
{
  // Return the timestamp as uint32 seconds since the epoch.
  //
  static uint32_t
  to_seconds (timestamp t) noexcept
  {
    const auto s (
      chrono::duration_cast<chrono::seconds> (t.time_since_epoch ()).count ());

    LIBOBE_PRE (s >= 0 && s <= numeric_limits<uint32_t>::max ());

    return static_cast<uint32_t> (s);
  }

  // file_header
  //
  void file_header::
  serialize (bit_serializer& s) const
  {
    s.next_uint64 (to_underlying (id));
    s.next_uint32 (to_seconds (created));
    s.next_uint32 (to_seconds (modified));
    s.next_bool (flags[0]);
    s.next_bool (flags[1]);
    s.next_uint64 (to_underlying (owner));
    s.next_string (name);
  }

  // file_store
  //
  file_store::
  ~file_store ()
  {
  }

  awaitable<file_header>
  publish (file_store& s, title_id t, string n, bytes d, timestamp now)
  {
    LIBOBE_PRE (!n.empty () && n.size () <= file_header::max_name);

    // Note that the client never reads the flags back (see file_header).
    //
    const optional<file_header> h (
      co_await s.upload (t,
                         publisher,
                         move (n),
                         {false, false},
                         move (d),
                         now,
                         numeric_limits<size_t>::max ()));

    // Uploading without a limit always succeeds.
    //
    LIBOBE_ASSERT (h);
    co_return *h;
  }

  // memory_file_store
  //
  awaitable<optional<stored_file>> memory_file_store::
  find (title_id t, file_id i)
  {
    auto j (files_.find (i));

    if (j == files_.end () || j->second.title != t)
      co_return nullopt;

    co_return j->second.file;
  }

  awaitable<vector<file_header>> memory_file_store::
  list (title_id t,
        optional<user_id> o,
        timestamp since,
        string prefix,
        size_t limit)
  {
    vector<file_header> r;
    for (const auto& [i, e]: files_)
    {
      if (r.size () == limit)
        break;

      const file_header& h (e.file.header);

      if (e.title == t                &&
          (!o || h.owner == *o)       &&
          h.modified >= since         &&
          h.name.starts_with (prefix))
        r.push_back (h);
    }

    co_return r;
  }

  awaitable<optional<file_header>> memory_file_store::
  upload (title_id t,
          user_id o,
          string n,
          array<bool, 2> fs,
          bytes d,
          timestamp now,
          size_t limit)
  {
    LIBOBE_PRE (!n.empty () && n.size () <= file_header::max_name);

    auto owned = [t, o] (const pair<const file_id, entry>& p)
    {
      return p.second.title == t && p.second.file.header.owner == o;
    };

    // See if the owner already has a file with this name and, if not,
    // whether it may have one more.
    //
    auto match = [&owned, &n] (const pair<const file_id, entry>& p)
    {
      return owned (p) && p.second.file.header.name == n;
    };

    auto i (ranges::find_if (files_, match));

    if (i == files_.end ())
    {
      if (static_cast<size_t> (ranges::count_if (files_, owned)) >= limit)
        co_return nullopt;

      const file_id id {++last_id_};

      file_header h;
      h.id = id;
      h.created = now;
      h.owner = o;
      h.name = move (n);

      i = files_.emplace (id, entry {t, stored_file {move (h), {}}}).first;
    }

    stored_file& f (i->second.file);
    f.header.modified = now;
    f.header.flags = fs;
    f.header.size = static_cast<uint32_t> (d.size ());
    f.data = move (d);

    co_return f.header;
  }

  awaitable<optional<file_header>> memory_file_store::
  update (title_id t, file_id i, bytes d, timestamp now)
  {
    auto j (files_.find (i));

    if (j == files_.end () || j->second.title != t)
      co_return nullopt;

    stored_file& f (j->second.file);
    f.header.modified = now;
    f.header.size = static_cast<uint32_t> (d.size ());
    f.data = move (d);

    co_return f.header;
  }
}
