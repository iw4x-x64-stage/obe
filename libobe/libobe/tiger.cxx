// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/tiger.hxx>

#include <cstring> // memcpy(), memset()

using namespace std;

namespace obe
{
  // The four S-boxes, 256 64-bit entries each.
  //
  using sboxes = uint64_t[4][256];

  static inline uint64_t
  load64 (const uint8_t* p) noexcept
  {
    uint64_t r (0);
    for (size_t i (0); i != 8; ++i)
      r |= static_cast<uint64_t> (p[i]) << (i * 8);
    return r;
  }

  static inline void
  store64 (uint8_t* p, uint64_t v) noexcept
  {
    for (size_t i (0); i != 8; ++i)
      p[i] = static_cast<uint8_t> (v >> (i * 8));
  }

  static inline uint8_t
  byte_of (uint64_t v, size_t i) noexcept
  {
    return static_cast<uint8_t> (v >> (i * 8));
  }

  // Compress one 64-byte block into the state using the specified S-boxes.
  //
  // This is the compression function from the Tiger paper, spelled out the
  // same way: three passes of eight rounds with the key schedule between
  // them, followed by the feedforward.
  //
  static void
  compress (const sboxes& t, uint64_t (&s)[3], const uint8_t* block) noexcept
  {
    uint64_t x[8];
    for (size_t i (0); i != 8; ++i)
      x[i] = load64 (block + i * 8);

    uint64_t a (s[0]), b (s[1]), c (s[2]);

    // Note that the arguments are rotated by each call (a, b, c), (b, c, a),
    // (c, a, b) rather than the values moved around.
    //
    auto round = [&t] (uint64_t& a, uint64_t& b, uint64_t& c,
                       uint64_t x,
                       uint64_t mul)
    {
      c ^= x;
      a -= t[0][byte_of (c, 0)] ^ t[1][byte_of (c, 2)] ^
           t[2][byte_of (c, 4)] ^ t[3][byte_of (c, 6)];
      b += t[3][byte_of (c, 1)] ^ t[2][byte_of (c, 3)] ^
           t[1][byte_of (c, 5)] ^ t[0][byte_of (c, 7)];
      b *= mul;
    };

    auto pass = [&round, &x] (uint64_t& a, uint64_t& b, uint64_t& c,
                              uint64_t mul)
    {
      round (a, b, c, x[0], mul);
      round (b, c, a, x[1], mul);
      round (c, a, b, x[2], mul);
      round (a, b, c, x[3], mul);
      round (b, c, a, x[4], mul);
      round (c, a, b, x[5], mul);
      round (a, b, c, x[6], mul);
      round (b, c, a, x[7], mul);
    };

    auto schedule = [&x] ()
    {
      x[0] -= x[7] ^ 0xA5A5A5A5A5A5A5A5ULL;
      x[1] ^= x[0];
      x[2] += x[1];
      x[3] -= x[2] ^ (~x[1] << 19);
      x[4] ^= x[3];
      x[5] += x[4];
      x[6] -= x[5] ^ (~x[4] >> 23);
      x[7] ^= x[6];
      x[0] += x[7];
      x[1] -= x[0] ^ (~x[7] << 19);
      x[2] ^= x[1];
      x[3] += x[2];
      x[4] -= x[3] ^ (~x[2] >> 23);
      x[5] ^= x[4];
      x[6] += x[5];
      x[7] -= x[6] ^ 0x0123456789ABCDEFULL;
    };

    pass (a, b, c, 5);
    schedule ();
    pass (c, a, b, 7);
    schedule ();
    pass (b, c, a, 9);

    s[0] = a ^ s[0];
    s[1] = b - s[1];
    s[2] = c + s[2];
  }

  static const uint64_t initial_state[3] = {
    0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL, 0xF096A5B4C3B2E187ULL};

  // Generate the S-boxes.
  //
  // The published Tiger tables are produced by a deterministic procedure
  // that starts from the identity bytes and shuffles each byte column using
  // the compression function itself (keyed by the tables generated so far)
  // over a fixed message. We run that procedure once instead of carrying 8K
  // of constants around. The tests verify the result through the reference
  // test vectors.
  //
  static sboxes&
  generate (sboxes& t) noexcept
  {
    // Start with each byte of entry i equal to i.
    //
    for (size_t k (0); k != 4; ++k)
    {
      for (size_t i (0); i != 256; ++i)
        t[k][i] = 0x0101010101010101ULL * (i & 0xff);
    }

    // Entry n of the table viewed as a single 1024-entry array.
    //
    auto entry = [&t] (size_t n) -> uint64_t& {return t[n / 256][n % 256];};

    auto swap_byte = [&entry] (size_t n, size_t m, size_t col)
    {
      uint64_t& u (entry (n));
      uint64_t& v (entry (m));

      const uint64_t mask (0xffULL << (col * 8));
      const uint64_t d ((u ^ v) & mask);

      u ^= d;
      v ^= d;
    };

    const char message[] =
      "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";

    uint8_t block[64];
    memcpy (block, message, 64);

    uint64_t state[3];
    memcpy (state, initial_state, sizeof (state));

    size_t abc (2);
    for (size_t pass (0); pass != 5; ++pass)
    {
      for (size_t i (0); i != 256; ++i)
      {
        for (size_t s (0); s != 1024; s += 256)
        {
          // Rekey the state every three column shuffles.
          //
          if (++abc == 3)
          {
            abc = 0;
            compress (t, state, block);
          }

          for (size_t col (0); col != 8; ++col)
          {
            const size_t j (s + byte_of (state[abc], col));
            swap_byte (s + i, j, col);
          }
        }
      }
    }

    return t;
  }

  static const sboxes&
  table ()
  {
    static sboxes t;
    static const sboxes& r (generate (t));
    return r;
  }

  void tiger::
  reset () noexcept
  {
    memcpy (state_, initial_state, sizeof (state_));
    count_ = 0;
    done_ = false;
    empty_ = true;
  }

  void tiger::
  compress () const noexcept
  {
    obe::compress (table (), state_, buf_);
  }

  void tiger::
  append (span<const uint8_t> d)
  {
    LIBOBE_PRE_MSG (!done_, "data appended after result extraction");

    if (d.empty ())
      return;

    // Fill the pending block, compressing it whenever it is full.
    //
    for (size_t i (0); i != d.size (); )
    {
      const size_t p (count_ % 64);
      const size_t n (min (d.size () - i, 64 - p));

      memcpy (buf_ + p, d.data () + i, n);
      count_ += n;
      i += n;

      if (count_ % 64 == 0)
        compress ();
    }

    empty_ = false;
  }

  void tiger::
  append (string_view s)
  {
    append (span<const uint8_t> (reinterpret_cast<const uint8_t*> (s.data ()),
                                 s.size ()));
  }

  const tiger::digest_type& tiger::
  binary () const
  {
    if (!done_)
    {
      // Pad with 0x01 followed by zeros up to 56 modulo 64 and append the
      // message length in bits.
      //
      const uint64_t bits (count_ * 8);
      size_t p (count_ % 64);

      buf_[p++] = 0x01;

      if (p > 56)
      {
        memset (buf_ + p, 0, 64 - p);
        compress ();
        p = 0;
      }

      memset (buf_ + p, 0, 56 - p);
      store64 (buf_ + 56, bits);
      compress ();

      for (size_t i (0); i != 3; ++i)
        store64 (bin_ + i * 8, state_[i]);

      done_ = true;
      str_[0] = '\0'; // Indicate we haven't computed the string yet.
    }

    return bin_;
  }

  static const char hex_map[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f'};

  const char* tiger::
  string () const
  {
    if (!done_)
      binary ();

    if (str_[0] == '\0')
    {
      for (size_t i (0); i != 24; ++i)
      {
        str_[i * 2]     = hex_map[bin_[i] >> 4];
        str_[i * 2 + 1] = hex_map[bin_[i] & 0x0f];
      }

      str_[48] = '\0';
    }

    return str_;
  }
}
