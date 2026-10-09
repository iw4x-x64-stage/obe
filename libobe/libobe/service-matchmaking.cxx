// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service-matchmaking.hxx>

#include <openssl/rand.h>

#include <libobe/openssl.hxx>

using namespace std;

namespace obe
{
  // The search queries of the title.
  //
  // A query takes its parameters and the session's attributes and returns
  // nullopt if the session doesn't match and its rank otherwise (the lower
  // the better).
  //
  using query_function =
    optional<uint64_t> (span<const int32_t> parameters,
                        span<const int32_t> attributes);

  struct query
  {
    size_t          parameters; // Number of parameters.
    query_function* function;
  };

  // The join in progress query (MatchMaking_JOIN_IN_PROGRESS_Query, id 2),
  // which the client searches for the lobbies to join with. Its parameters
  // are:
  //
  // 0 lobby type          (8 or, in ranked matches, 7)
  // 1 playlist id
  // 2 protocol version
  // 3 map packs           (bit flags the party can play the playlist with)
  // 4 playlist version
  // 5 party size
  // 6 party skill         (average performance value; see performance)
  //
  // And the host's session attributes (MatchMakingInfo) are:
  //
  // 0 lobby type          (8)
  // 1 playlist id
  // 2 playlist version
  // 3 playlist number
  // 4 protocol version
  // 5 map packs           (bit flags the lobby plays the playlist with)
  // 6 playlist id         (again)
  // 7 free slots
  // 8 lobby skill         (average performance value of the members)
  //
  // The query itself is defined on the server, so the matching is inferred
  // from what the client sends and the host registers: the lobby must be of
  // the same type, playlist, playlist version, and protocol version, only
  // use the map packs the party has, and have room for the party. The
  // lobbies are ranked by how close their skill is to the party's.
  //
  static optional<uint64_t>
  join_in_progress (span<const int32_t> p, span<const int32_t> a)
  {
    // Skip the sessions registered by something else than the title.
    //
    if (a.size () < 9)
      return nullopt;

    if (a[0] != p[0] || // Lobby type.
        a[1] != p[1] || // Playlist id.
        a[2] != p[4] || // Playlist version.
        a[4] != p[2])   // Protocol version.
      return nullopt;

    if ((a[5] & ~p[3]) != 0) // Map packs.
      return nullopt;

    if (a[7] < p[5]) // Free slots.
      return nullopt;

    return static_cast<uint64_t> (
      abs (static_cast<int64_t> (a[8]) - static_cast<int64_t> (p[6])));
  }

  static const map<int32_t, query> queries
  {
    {2, {7, &join_in_progress}}
  };

  // session_info
  //
  session_info::
  session_info (bit_parser& p)
  {
    p.next_blob (address);
    p.next_blob (id);
    p.next_blob (key);

    available_public  = p.next_int32 ();
    occupied_public   = p.next_int32 ();
    available_private = p.next_int32 ();
    occupied_private  = p.next_int32 ();

    while (p.peek () == bit_type::int32)
    {
      if (attributes.size () == max_attributes)
        throw bit_parsing (p.name (),
                           p.position (),
                           format ("more than {} session attributes",
                                   max_attributes));

      attributes.push_back (p.next_int32 ());
    }
  }

  void session_info::
  serialize (bit_serializer& s) const
  {
    s.next_blob (address);
    s.next_blob (id);
    s.next_blob (key);

    s.next_int32 (available_public);
    s.next_int32 (occupied_public);
    s.next_int32 (available_private);
    s.next_int32 (occupied_private);

    for (int32_t a: attributes)
      s.next_int32 (a);
  }

  // matchmaking
  //
  matchmaking_service::
  matchmaking_service (matchmaking_settings s)
    : settings_ (move (s))
  {
  }

  awaitable<void> matchmaking_service::
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer& out)
  {
    in.next_uint8 (); // Reserved.

    switch (op)
    {
      case 1: create (id, in, out); break;
      case 2: modify (id, in);      break;
      case 3: remove (id, in);      break;
      case 5: search (id, in, out); break;
      default:
        throw task_error (lsg_error::service_not_available,
                          "matchmaking operation {} not supported", op);
    }

    co_return;
  }

  void matchmaking_service::
  disconnect (const lsg_identity& id) noexcept
  {
    erase_if (sessions_, [&id] (const auto& p)
    {
      return p.second.connection == id.connection;
    });
  }

  map<session_id, matchmaking_service::session>::iterator matchmaking_service::
  find (const lsg_identity& id, const session_id& s)
  {
    auto i (sessions_.find (s));

    // Note that we don't reveal the sessions of other titles.
    //
    if (i == sessions_.end () || i->second.title != id.title)
      throw task_error (lsg_error::no_entry_to_update, "unknown session");

    // Only the host may change its session. We check the user rather than
    // the connection so that the host can reconnect.
    //
    if (i->second.owner != id.user)
      throw task_error (lsg_error::permission_denied,
                        "session is owned by user {}",
                        to_underlying (i->second.owner));

    return i;
  }

  void matchmaking_service::
  create (const lsg_identity& id, bit_parser& in, bit_serializer& out)
  {
    session_info si (in);

    // Make sure the connection doesn't hoard sessions.
    //
    auto hosted = [&id] (const auto& p)
    {
      return p.second.connection == id.connection;
    };

    if (ranges::count_if (sessions_, hosted) >=
        static_cast<ptrdiff_t> (settings_.max_hosted))
      throw task_error (lsg_error::permission_denied,
                        "more than {} hosted sessions",
                        settings_.max_hosted);

    // Generate the session id (unique among the current sessions) and the
    // key exchange key.
    //
    do
    {
      if (RAND_bytes (si.id.data (), static_cast<int> (si.id.size ())) != 1)
        throw_crypto_error ("unable to generate session id");
    }
    while (sessions_.contains (si.id));

    if (RAND_bytes (si.key.data (), static_cast<int> (si.key.size ())) != 1)
      throw_crypto_error ("unable to generate session key");

    out.next_uint32 (1);
    out.next_blob (si.id);
    out.next_blob (si.key);

    const session_id sid (si.id);
    sessions_.emplace (
      sid,
      session {id.title, id.user, id.connection, move (si)});
  }

  void matchmaking_service::
  modify (const lsg_identity& id, bit_parser& in)
  {
    session_info si (in);

    auto i (find (id, si.id));

    // The key is ours, so keep it whatever the client sends.
    //
    si.key = i->second.info.key;
    i->second.info = move (si);
  }

  void matchmaking_service::
  remove (const lsg_identity& id, bit_parser& in)
  {
    session_id s;
    in.next_blob (s);

    sessions_.erase (find (id, s));
  }

  void matchmaking_service::
  search (const lsg_identity& id, bit_parser& in, bit_serializer& out)
  {
    // Parse the query (see above).
    //
    const int32_t qid (in.next_int32 ());
    const int32_t limit (in.next_int32 ());

    vector<int32_t> ps;
    while (in.peek () == bit_type::int32)
    {
      if (ps.size () == session_info::max_attributes)
        throw bit_parsing (in.name (),
                           in.position (),
                           format ("more than {} query parameters",
                                   session_info::max_attributes));

      ps.push_back (in.next_int32 ());
    }

    auto i (queries.find (qid));
    if (i == queries.end ())
      throw task_error (lsg_error::invalid_query_id, "unknown query {}", qid);

    const query& q (i->second);

    if (ps.size () != q.parameters)
      throw task_error (lsg_error::parameter_parse_error,
                        "query {} with {} parameters instead of {}",
                        qid, ps.size (), q.parameters);

    // Rank the matching sessions of the title and reply with the best ones,
    // but no more than the client asked for. Note that we include the
    // client's own sessions: the client recognizes and skips them.
    //
    vector<pair<uint64_t, const session_info*>> r;
    for (const auto& [s, e]: sessions_)
    {
      if (e.title != id.title)
        continue;

      if (optional<uint64_t> k = q.function (ps, e.info.attributes))
        r.emplace_back (*k, &e.info);
    }

    ranges::stable_sort (r,
                         {},
                         &pair<uint64_t, const session_info*>::first);

    r.resize (min ({r.size (),
                    settings_.max_results,
                    static_cast<size_t> (max (limit, 0))}));

    out.next_uint32 (static_cast<uint32_t> (r.size ()));

    for (const auto& [k, si]: r)
      si->serialize (out);
  }
}
