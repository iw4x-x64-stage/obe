// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/crypto.hxx>
#include <libobe/frame-cipher.hxx> // session_key

#include <libobe/export.hxx>

namespace obe
{
  // The authentication tickets.
  //
  // On successful authentication the client receives two 128-byte tickets.
  // The client ticket is for the client: it decodes it to obtain the session
  // key. The server ticket is opaque to the client, which presents it to
  // the lobby service gateway in the connection handshake. That's how the
  // gateway learns who the client is and what session key to use, without
  // sharing any state with the authentication server.
  //
  static constexpr size_t ticket_size = 128;

  using ticket_data = array<uint8_t, ticket_size>;

  // The client ticket (bdAuthTicket).
  //
  // Its binary representation is (integers are little-endian):
  //
  // uint32   magic          0xEFBDADDE
  // uint8    type
  // uint32   title id
  // uint32   time issued    Seconds since the UNIX epoch.
  // uint32   time expires   As above.
  // uint64   license id
  // uint64   user id
  // char[64] user name      '\0'-terminated.
  // uint8[24] session key
  // ...      zero padding
  //
  // The client only checks the magic and uses the title id (which it sends
  // back in the gateway handshake) and the session key. The field names
  // other than these are recovered from their use and position.
  //
  // Invariants: the user name is at most 63 characters long and contains no
  // '\0'. The times are representable as uint32 seconds.
  //
  struct LIBOBE_SYMEXPORT client_ticket
  {
    static constexpr uint32_t magic = 0xEFBDADDE;
    static constexpr size_t max_user_name = 63;

    uint8_t     type;
    title_id    title;
    timestamp   issued;
    timestamp   expires;
    license_id  license;
    user_id     user;
    string      user_name;
    session_key key;

    // Create the ticket. The arguments must satisfy the invariants.
    //
    client_ticket (uint8_t type,
                   title_id,
                   timestamp issued,
                   timestamp expires,
                   license_id,
                   user_id,
                   string user_name,
                   const session_key&);

    // Parse the binary representation. Throw invalid_argument if it is
    // invalid (wrong magic, missing user name terminator, etc).
    //
    explicit
    client_ticket (span<const uint8_t, ticket_size>);

    ticket_data
    binary () const;
  };

  // The server ticket.
  //
  // This is our own format: the protocol only requires it to be 128 bytes,
  // which the gateway gets back verbatim. Its binary representation is the
  // following plaintext sealed with AES-256-GCM (see ticket_sealer):
  //
  // uint8     version       1
  // uint32    title id
  // uint32    time issued
  // uint32    time expires
  // uint64    license id
  // uint64    user id
  // uint8[24] session key
  // ...       zero padding
  //
  // The user name is not included (it doesn't fit next to the AEAD overhead)
  // and the gateway looks it up by the user id.
  //
  // Invariants: the times are representable as uint32 seconds.
  //
  struct server_ticket
  {
    title_id    title;
    timestamp   issued;
    timestamp   expires;
    license_id  license;
    user_id     user;
    session_key key;

    // Return true if the ticket is expired at the specified time.
    //
    bool
    expired (timestamp t) const noexcept {return t >= expires;}
  };

  // Return a new random session key. Throw std::system_error (in the
  // crypto_category()) if the random generator fails.
  //
  LIBOBE_SYMEXPORT session_key
  generate_session_key ();

  // The server ticket sealing key.
  //
  using ticket_key = array<uint8_t, 32>;

  // Return a new random ticket sealing key. Throw std::system_error (in the
  // crypto_category()) if the random generator fails.
  //
  LIBOBE_SYMEXPORT ticket_key
  generate_ticket_key ();

  // Seal and open the server tickets.
  //
  // Throw std::system_error (in the crypto_category()) if the underlying
  // cryptographic library fails.
  //
  class LIBOBE_SYMEXPORT ticket_sealer
  {
  public:
    explicit
    ticket_sealer (const ticket_key& k): key_ (k) {}

    // Seal the ticket with a random nonce. The ticket must satisfy its
    // invariants.
    //
    ticket_data
    seal (const server_ticket&) const;

    // Open the sealed ticket. Throw invalid_argument if it was not sealed
    // with this key, was tampered with, or has an unknown version.
    //
    server_ticket
    open (span<const uint8_t, ticket_size>) const;

  private:
    ticket_key key_;
  };
}
