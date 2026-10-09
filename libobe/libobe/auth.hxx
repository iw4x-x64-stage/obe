// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/ticket.hxx> // ticket_data

#include <libobe/export.hxx>

namespace obe
{
  // The authentication (auth3) messages.
  //
  // The client authenticates by POSTing the request to /auth/ over HTTPS
  // with the platform token in the Authorization header and receives the
  // reply in the response body (with the 200 status even for the error
  // replies). Both are JSON objects:
  //
  // {"auth_task": "44", "iv_seed": "<uint32>", "title_id": "<uint32>"}
  //
  // {"auth_task": 45, "code": 700, "iv_seed": <uint32>,
  //  "client_ticket": "<base64>", "server_ticket": "<base64>",
  //  "extra_data": "{\"sbx\": \"<sandbox>\", \"dpi\": \"<platform>\"}"}
  //
  // {"auth_task": 45, "code": <error>}
  //
  // The request writes its numbers as strings of decimal digits, since the
  // client's makeAuthForXBoxOne() sets them with bdJSON::setUInt64(), which
  // formats them with %llu. The reply writes them as numbers, and the client
  // reads both forms. Note also that extra_data is a string containing JSON
  // rather than an object.
  //
  // The client uses the reply's iv_seed as the initial gateway frame seed.
  //
  // When parsing, unknown object members are ignored.

  struct LIBOBE_SYMEXPORT auth_request
  {
    static constexpr uint64_t task = 44;

    uint32_t iv_seed;
    title_id title;

    auth_request (uint32_t s, title_id t): iv_seed (s), title (t) {}

    // Parse the JSON representation. Throw invalid_argument if it is
    // invalid.
    //
    explicit
    auth_request (string_view json);

    // Return the JSON representation.
    //
    string
    json () const;
  };

  // The successful authentication outcome.
  //
  struct auth_grant
  {
    uint32_t    iv_seed;
    ticket_data client;   // Client ticket (see client_ticket).
    ticket_data server;   // Server ticket (see ticket_sealer).
    string      sandbox;  // "sbx", for example, RETAIL.
    string      platform; // "dpi", device platform info.
  };

  // The reply codes the server uses. The client only distinguishes success
  // and logs the rest. The values are those of the client's error names:
  //
  enum class auth_code: uint32_t
  {
    success      = 700, // BD_AUTH_NO_ERROR
    bad_request  = 701, // BD_AUTH_BAD_REQUEST
    server_error = 702, // BD_AUTH_SERVER_CONFIG_ERROR
    bad_title    = 703, // BD_AUTH_BAD_TITLE_ID
    bad_account  = 704  // BD_AUTH_BAD_ACCOUNT
  };

  // Invariants: the grant is present if and only if the code is success.
  //
  struct LIBOBE_SYMEXPORT auth_reply
  {
    static constexpr uint64_t task = 45;
    static constexpr uint32_t success = to_underlying (auth_code::success);

    uint32_t             code;
    optional<auth_grant> grant;

    // Create a successful reply.
    //
    explicit
    auth_reply (auth_grant g): code (success), grant (move (g)) {}

    // Create an error reply. The code must not be success.
    //
    explicit
    auth_reply (uint32_t code);

    explicit
    auth_reply (auth_code c): auth_reply (to_underlying (c)) {}

    // Parse the JSON representation. Throw invalid_argument if it is
    // invalid.
    //
    explicit
    auth_reply (string_view json);

    // Return the JSON representation.
    //
    string
    json () const;
  };
}
