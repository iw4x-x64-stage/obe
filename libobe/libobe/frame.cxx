// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/frame.hxx>

#include <limits> // numeric_limits

using namespace std;

namespace obe
{
  static inline uint32_t
  load32 (const uint8_t* p) noexcept
  {
    return static_cast<uint32_t> (p[0])       |
           static_cast<uint32_t> (p[1]) << 8  |
           static_cast<uint32_t> (p[2]) << 16 |
           static_cast<uint32_t> (p[3]) << 24;
  }

  static inline void
  append32 (bytes& b, uint32_t v)
  {
    for (size_t i (0); i != 4; ++i)
      b.push_back (static_cast<uint8_t> (v >> (i * 8)));
  }

  static const uint32_t server_magic (0xDEADBEEF);

  // frame_prelude
  //
  frame_prelude::
  frame_prelude (span<const uint8_t, size> d)
    : version (load32 (d.data ())),
      receive_capacity (load32 (d.data () + 4))
  {
    if (version != current_version)
      throw invalid_input ("unsupported protocol version {}", version);
  }

  // frame_type
  //
  const char*
  to_string (frame_type t) noexcept
  {
    switch (t)
    {
      case frame_type::task_reply:    return "task reply";
      case frame_type::push:          return "push";
      case frame_type::error:         return "error";
      case frame_type::connection_id: return "connection id";
      case frame_type::service_reply: return "service reply";
    }

    return "unknown frame type";
  }

  // frame_parsing
  //
  static inline string
  message (const string& n, uint64_t p, const string& d)
  {
    return n.empty ()
      ? format ("{}: error: {}", p, d)
      : format ("{}:{}: error: {}", n, p, d);
  }

  frame_parsing::
  frame_parsing (const string& n, uint64_t p, const string& d)
    : runtime_error (message (n, p, d)),
      name (n), position (p), description (d)
  {
  }

  // frame_parser
  //
  frame_parser::
  frame_parser (const string& n, size_t m)
    : name_ (n),
      max_size_ (m),
      begin_ (0),
      position_ (0)
  {
  }

  void frame_parser::
  append (span<const uint8_t> d)
  {
    // Drop the parsed data before growing the buffer so that it doesn't
    // grow indefinitely over the connection lifetime.
    //
    if (begin_ != 0)
    {
      buffer_.erase (buffer_.begin (),
                     buffer_.begin () + static_cast<ptrdiff_t> (begin_));
      begin_ = 0;
    }

    buffer_.insert (buffer_.end (), d.begin (), d.end ());
  }

  optional<frame> frame_parser::
  next (const frame_cipher* c)
  {
    for (;;)
    {
      const span<const uint8_t> d (buffer_.data () + begin_,
                                   buffer_.size () - begin_);

      // Parse the size and see if the whole frame is there.
      //
      if (d.size () < 4)
        return nullopt;

      const uint32_t n (load32 (d.data ()));

      if (n > max_size_)
        fail ("frame of {} bytes exceeds maximum size of {} bytes",
              n, max_size_);

      if (d.size () - 4 < n)
        return nullopt;

      // Skip the keepalive.
      //
      if (n == 0)
      {
        begin_ += 4;
        position_ += 4;
        continue;
      }

      const span<const uint8_t> f (d.subspan (4, n));

      frame r;
      switch (f[0])
      {
        case 0:
        {
          r.encrypted = false;
          r.seed = 0;
          r.payload.assign (f.begin () + 1, f.end ());
          break;
        }
        case 1:
        {
          if (c == nullptr)
            fail ("encrypted frame before session key is established");

          // Flag, seed, and at least one cipher block.
          //
          if (n < 5 + frame_cipher::block_size ||
              (n - 5) % frame_cipher::block_size != 0)
            fail ("invalid encrypted frame size {}", n);

          r.encrypted = true;
          r.seed = load32 (f.data () + 1);

          bytes p (f.begin () + 5, f.end ());
          c->decrypt (r.seed, p);

          // Verify the MAC (see the format description for the range).
          //
          const frame_cipher::mac_type m (
            c->authenticate (span (p).subspan (5)));

          if (!equal (m.begin (), m.end (), p.begin ()))
            fail ("encrypted frame authentication failed");

          p.erase (p.begin (), p.begin () + 4);
          r.payload = move (p);
          break;
        }
        default:
          fail ("invalid frame encryption flag {}", f[0]);
      }

      begin_ += 4 + n;
      position_ += 4 + n;
      return r;
    }
  }

  // frame_serializer
  //
  void frame_serializer::
  next (frame_type t, span<const uint8_t> p)
  {
    LIBOBE_PRE (p.size () <= numeric_limits<uint32_t>::max () - 2);

    append32 (out_, static_cast<uint32_t> (p.size () + 2));
    out_.push_back (0);
    out_.push_back (static_cast<uint8_t> (t));
    out_.insert (out_.end (), p.begin (), p.end ());
  }

  void frame_serializer::
  next (frame_type t,
        span<const uint8_t> p,
        const frame_cipher& c,
        uint32_t seed)
  {
    const size_t bs (frame_cipher::block_size);

    LIBOBE_PRE (p.size () <= numeric_limits<uint32_t>::max () - 5 - 2 * bs);

    // Assemble the plaintext (padded with zeros) in place and encrypt it.
    //
    const size_t n ((5 + p.size () + bs - 1) / bs * bs);

    append32 (out_, static_cast<uint32_t> (n + 5));
    out_.push_back (1);
    append32 (out_, seed);

    const size_t b (out_.size ());

    append32 (out_, server_magic);
    out_.push_back (static_cast<uint8_t> (t));
    out_.insert (out_.end (), p.begin (), p.end ());
    out_.resize (b + n, 0);

    c.encrypt (seed, span (out_).subspan (b));
  }

  size_t frame_serializer::
  size (size_t p, bool e) noexcept
  {
    const size_t bs (frame_cipher::block_size);

    return e
      ? (5 + p + bs - 1) / bs * bs + 5 // Flag, seed, padded ciphertext.
      : p + 2;                         // Flag, type.
  }

  void frame_serializer::
  next_keepalive ()
  {
    append32 (out_, 0);
  }
}
