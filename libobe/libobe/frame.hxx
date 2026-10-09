// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <format>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/frame-cipher.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The lobby service gateway (LSG) connection framing.
  //
  // The connection starts with the client sending the prelude, 8 raw bytes
  // (all integers are little-endian):
  //
  // uint32 version          Always 180.
  // uint32 receive capacity Size of the client's receive buffer.
  //
  // After that both sides exchange frames:
  //
  // uint32 size             Size of the rest of the frame.
  // uint8  encrypted        1 if encrypted, 0 otherwise.
  // ...
  //
  // A frame with zero size (and nothing else, not even the encrypted flag)
  // is a keepalive.
  //
  // A plain client frame continues with the payload. An encrypted client
  // frame continues with the uint32 seed and the ciphertext of the
  // following plaintext (see frame_cipher for the encryption):
  //
  // uint8[4] mac            Truncated HMAC of the plaintext from byte 5.
  // ...      payload
  // ...      padding        Up to the block size, each the seed's low byte.
  //
  // Note that the MAC skips the first payload byte, which is presumably an
  // off-by-one in the original implementation that we have to reproduce.
  //
  // A server frame carries the message type (frame_type) before the
  // payload. A plain server frame continues with:
  //
  // uint8  type
  // ...    payload
  //
  // And an encrypted server frame with the uint32 seed and the ciphertext
  // of the following plaintext:
  //
  // uint32 magic            Always 0xDEADBEEF.
  // uint8  type
  // ...    payload
  // ...    padding          Up to the block size, zeros.
  //
  // Note that in both directions the padding becomes part of the payload on
  // the receiving side: the payload formats are self-delimiting (bit
  // buffers end with the end-of-request marker) or tolerate trailing data.

  // The prelude.
  //
  struct LIBOBE_SYMEXPORT frame_prelude
  {
    static constexpr uint32_t current_version = 180;
    static constexpr size_t size = 8;

    uint32_t version;
    uint32_t receive_capacity;

    // Parse the prelude. Throw invalid_argument if the version is not the
    // current one.
    //
    explicit
    frame_prelude (span<const uint8_t, size>);
  };

  // Server message types.
  //
  enum class frame_type: uint8_t
  {
    task_reply    = 1, // Bit buffer task reply.
    push          = 2, // Push message.
    error         = 3, // Gateway error (uint32 code).
    connection_id = 4, // Connection id (uint64).
    service_reply = 5  // Byte buffer task reply.
  };

  LIBOBE_SYMEXPORT const char*
  to_string (frame_type) noexcept;

  inline ostream&
  operator<< (ostream& os, frame_type t) {return os << to_string (t);}

  // A client frame.
  //
  struct frame
  {
    bool     encrypted;
    uint32_t seed;     // Only if encrypted.
    bytes    payload;  // Plaintext (with padding if encrypted).
  };

  class LIBOBE_SYMEXPORT frame_parsing: public runtime_error
  {
  public:
    frame_parsing (const string& name,
                   uint64_t position,
                   const string& description);

    string name;
    uint64_t position; // Byte offset of the frame in the stream.
    string description;
  };

  // Parse the client frames from the connection byte stream.
  //
  // The data is appended as it arrives and the complete frames are then
  // extracted one by one with next(), which skips keepalives, decrypts and
  // authenticates the encrypted frames, and throws frame_parsing if the
  // stream is invalid. After an exception the stream is out of sync and the
  // connection should be closed.
  //
  // Note that the prelude is not part of the frame stream.
  //
  class LIBOBE_SYMEXPORT frame_parser
  {
  public:
    // Frames (the size field value) larger than the maximum size are
    // rejected. The name is used in diagnostics.
    //
    frame_parser (const string& name, size_t max_size);

    frame_parser (const frame_parser&) = delete;
    frame_parser& operator= (const frame_parser&) = delete;

    const string&
    name () const noexcept {return name_;}

    // Append the received data.
    //
    void
    append (span<const uint8_t>);

    // Return the next complete frame or nullopt if more data is needed. The
    // cipher is required to decrypt encrypted frames and receiving one
    // without a cipher is an error.
    //
    optional<frame>
    next (const frame_cipher*);

  private:
    template <formattable_argument... A>
    [[noreturn]] void
    fail (std::format_string<A...>, A&&...) const;

  private:
    const string name_;
    size_t       max_size_;

    bytes    buffer_;
    size_t   begin_;    // Start of unparsed data in buffer_.
    uint64_t position_; // Stream offset of begin_.
  };

  // Serialize the server frames.
  //
  // The frames are appended to the specified byte sequence, which should
  // outlive the serializer.
  //
  class LIBOBE_SYMEXPORT frame_serializer
  {
  public:
    explicit
    frame_serializer (bytes& out): out_ (out) {}

    frame_serializer (const frame_serializer&) = delete;
    frame_serializer& operator= (const frame_serializer&) = delete;

    // Serialize a plain frame.
    //
    void
    next (frame_type, span<const uint8_t> payload);

    // Serialize an encrypted frame.
    //
    void
    next (frame_type,
          span<const uint8_t> payload,
          const frame_cipher&,
          uint32_t seed);

    void
    next_keepalive ();

    // Return the size field value of the frame with the payload of the
    // specified size.
    //
    static size_t
    size (size_t payload, bool encrypted) noexcept;

  private:
    bytes& out_;
  };
}

#include <libobe/frame.txx>
