// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/auth.hxx>

#include <format>
#include <limits> // numeric_limits

#include <boost/json.hpp>

#include <libobe/base64.hxx>

using namespace std;

namespace obe
{
  namespace json = boost::json;

  // Parse the JSON text as an object. The what argument names the message
  // in diagnostics.
  //
  static json::object
  parse_object (string_view s, const char* what)
  {
    boost::system::error_code ec;
    json::value v (json::parse (s, ec));

    if (ec)
      throw invalid_input ("invalid {}: {}", what, ec.message ());

    if (!v.is_object ())
      throw invalid_input ("invalid {}: object expected", what);

    return move (v.as_object ());
  }

  // Return the object member or throw invalid_input if it is missing.
  //
  static const json::value&
  member (const json::object& o, const char* n, const char* what)
  {
    const json::value* r (o.if_contains (n));

    if (r == nullptr)
      throw invalid_input ("invalid {}: missing '{}' member", what, n);

    return *r;
  }

  // Return the unsigned integer member value, verifying it doesn't exceed
  // the maximum.
  //
  static uint64_t
  unsigned_member (const json::object& o,
                   const char* n,
                   uint64_t max,
                   const char* what)
  {
    const json::value& v (member (o, n, what));

    // Note that Boost.JSON parses non-negative integers that fit int64 as
    // int64.
    //
    optional<uint64_t> r;
    if (v.is_uint64 ())
      r = v.get_uint64 ();
    else if (v.is_int64 () && v.get_int64 () >= 0)
      r = static_cast<uint64_t> (v.get_int64 ());

    if (!r || *r > max)
      throw invalid_input ("invalid {}: invalid '{}' member value", what, n);

    return *r;
  }

  static string_view
  string_member (const json::object& o, const char* n, const char* what)
  {
    const json::value& v (member (o, n, what));

    if (!v.is_string ())
      throw invalid_input ("invalid {}: '{}' member is not a string",
                           what, n);

    return v.get_string ();
  }

  static void
  expect_task (const json::object& o, uint64_t t, const char* what)
  {
    const uint64_t v (unsigned_member (o,
                                       "auth_task",
                                       numeric_limits<uint64_t>::max (),
                                       what));
    if (v != t)
      throw invalid_input ("invalid {}: auth task {} instead of {}",
                           what, v, t);
  }

  // auth_request
  //
  // Note that in the json() members json names the member function rather
  // than the namespace, so there we spell boost::json.
  //
  auth_request::
  auth_request (string_view s)
  {
    const char* what ("auth request");
    const json::object o (parse_object (s, what));

    expect_task (o, task, what);

    const uint64_t u32 (numeric_limits<uint32_t>::max ());

    iv_seed = static_cast<uint32_t> (unsigned_member (o, "iv_seed", u32, what));
    title = title_id {
      static_cast<uint32_t> (unsigned_member (o, "title_id", u32, what))};
  }

  string auth_request::
  json () const
  {
    boost::json::object o;
    o["auth_task"] = task;
    o["iv_seed"] = iv_seed;
    o["title_id"] = to_underlying (title);
    return boost::json::serialize (o);
  }

  // auth_reply
  //
  auth_reply::
  auth_reply (uint32_t c)
    : code (c)
  {
    LIBOBE_PRE (c != success);
  }

  auth_reply::
  auth_reply (string_view s)
  {
    const char* what ("auth reply");
    const json::object o (parse_object (s, what));

    expect_task (o, task, what);

    const uint64_t u32 (numeric_limits<uint32_t>::max ());

    code = static_cast<uint32_t> (unsigned_member (o, "code", u32, what));

    if (code != success)
      return;

    auth_grant g;
    g.iv_seed = static_cast<uint32_t> (
      unsigned_member (o, "iv_seed", u32, what));

    // Decode the tickets.
    //
    auto ticket = [&o, what] (const char* n)
    {
      const string_view v (string_member (o, n, what));

      bytes d;
      try
      {
        d = base64_decode (v);
      }
      catch (const invalid_argument& e)
      {
        throw invalid_input ("invalid {}: '{}' member: {}",
                             what, n, e.what ());
      }

      if (d.size () != ticket_size)
        throw invalid_input (
          "invalid {}: '{}' member is {} bytes instead of {}",
          what, n, d.size (), ticket_size);

      ticket_data r;
      copy (d.begin (), d.end (), r.begin ());
      return r;
    };

    g.client = ticket ("client_ticket");
    g.server = ticket ("server_ticket");

    // Parse the extra data, which is JSON inside a string.
    //
    {
      const json::object e (
        parse_object (string_member (o, "extra_data", what),
                      "auth reply extra data"));

      g.sandbox = string_member (e, "sbx", "auth reply extra data");
      g.platform = string_member (e, "dpi", "auth reply extra data");
    }

    grant = move (g);
  }

  string auth_reply::
  json () const
  {
    boost::json::object o;
    o["auth_task"] = task;
    o["code"] = code;

    if (grant)
    {
      boost::json::object e;
      e["sbx"] = grant->sandbox;
      e["dpi"] = grant->platform;

      o["iv_seed"] = grant->iv_seed;
      o["client_ticket"] = base64_encode (grant->client);
      o["server_ticket"] = base64_encode (grant->server);
      o["extra_data"] = boost::json::serialize (e);
    }

    return boost::json::serialize (o);
  }
}
