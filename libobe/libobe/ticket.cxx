// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/ticket.hxx>

#include <limits>   // numeric_limits
#include <cstring>  // memcpy(), memchr()
#include <concepts> // unsigned_integral

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <libobe/openssl.hxx>

using namespace std;

namespace obe
{
  // Little-endian packing of the ticket fields.
  //
  // The packer appends to a fixed-size buffer and the unpacker reads from
  // one. Both treat running past the end as a programming error since the
  // layouts are fixed and fit by construction.
  //
  namespace
  {
    class packer
    {
    public:
      explicit
      packer (span<uint8_t> d): data_ (d), position_ (0) {}

      void
      next (std::unsigned_integral auto v)
      {
        LIBOBE_PRE (position_ + sizeof (v) <= data_.size ());

        for (size_t i (0); i != sizeof (v); ++i)
          data_[position_++] = static_cast<uint8_t> (v >> (i * 8));
      }

      void
      next (span<const uint8_t> d)
      {
        LIBOBE_PRE (position_ + d.size () <= data_.size ());

        memcpy (data_.data () + position_, d.data (), d.size ());
        position_ += d.size ();
      }

    private:
      span<uint8_t> data_;
      size_t        position_;
    };

    class unpacker
    {
    public:
      explicit
      unpacker (span<const uint8_t> d): data_ (d), position_ (0) {}

      template <std::unsigned_integral T>
      T
      next ()
      {
        LIBOBE_PRE (position_ + sizeof (T) <= data_.size ());

        T r (0);
        for (size_t i (0); i != sizeof (T); ++i)
          r |= static_cast<T> (static_cast<T> (data_[position_++]) << (i * 8));
        return r;
      }

      span<const uint8_t>
      next (size_t n)
      {
        LIBOBE_PRE (position_ + n <= data_.size ());

        span<const uint8_t> r (data_.subspan (position_, n));
        position_ += n;
        return r;
      }

    private:
      span<const uint8_t> data_;
      size_t              position_;
    };
  }

  // Convert between timestamps and the uint32 seconds on the wire.
  //
  static inline bool
  representable (timestamp t) noexcept
  {
    const auto s (
      chrono::duration_cast<chrono::seconds> (t.time_since_epoch ()).count ());

    return s >= 0 && s <= numeric_limits<uint32_t>::max ();
  }

  static inline uint32_t
  to_seconds (timestamp t) noexcept
  {
    LIBOBE_PRE (representable (t));

    return static_cast<uint32_t> (
      chrono::duration_cast<chrono::seconds> (t.time_since_epoch ()).count ());
  }

  static inline timestamp
  from_seconds (uint32_t s) noexcept
  {
    return timestamp (chrono::seconds (s));
  }

  // client_ticket
  //
  client_ticket::
  client_ticket (uint8_t t,
                 title_id ti,
                 timestamp is,
                 timestamp ex,
                 license_id l,
                 user_id u,
                 string n,
                 const session_key& k)
    : type (t),
      title (ti),
      issued (is),
      expires (ex),
      license (l),
      user (u),
      user_name (move (n)),
      key (k)
  {
    LIBOBE_PRE (user_name.size () <= max_user_name);
    LIBOBE_PRE (user_name.find ('\0') == string::npos);
    LIBOBE_PRE (representable (issued) && representable (expires));
  }

  client_ticket::
  client_ticket (span<const uint8_t, ticket_size> d)
  {
    unpacker u (d);

    if (u.next<uint32_t> () != magic)
      throw invalid_input ("invalid client ticket magic");

    type    = u.next<uint8_t> ();
    title   = title_id {u.next<uint32_t> ()};
    issued  = from_seconds (u.next<uint32_t> ());
    expires = from_seconds (u.next<uint32_t> ());
    license = license_id {u.next<uint64_t> ()};
    user    = user_id {u.next<uint64_t> ()};

    {
      const span<const uint8_t> n (u.next (max_user_name + 1));
      const void* e (memchr (n.data (), '\0', n.size ()));

      if (e == nullptr)
        throw invalid_input ("unterminated client ticket user name");

      user_name.assign (reinterpret_cast<const char*> (n.data ()),
                        static_cast<const uint8_t*> (e) - n.data ());
    }

    {
      const span<const uint8_t> k (u.next (key.size ()));
      copy (k.begin (), k.end (), key.begin ());
    }
  }

  ticket_data client_ticket::
  binary () const
  {
    ticket_data r {}; // Zero padding.
    packer p (r);

    p.next (magic);
    p.next (type);
    p.next (to_underlying (title));
    p.next (to_seconds (issued));
    p.next (to_seconds (expires));
    p.next (to_underlying (license));
    p.next (to_underlying (user));

    {
      array<uint8_t, max_user_name + 1> n {};
      memcpy (n.data (), user_name.data (), user_name.size ());
      p.next (n);
    }

    p.next (key);
    return r;
  }

  session_key
  generate_session_key ()
  {
    session_key r;

    if (RAND_bytes (r.data (), static_cast<int> (r.size ())) != 1)
      throw_crypto_error ("unable to generate session key");

    return r;
  }

  ticket_key
  generate_ticket_key ()
  {
    ticket_key r;

    if (RAND_bytes (r.data (), static_cast<int> (r.size ())) != 1)
      throw_crypto_error ("unable to generate ticket key");

    return r;
  }

  // ticket_sealer
  //
  // The sealed ticket is the nonce, the ciphertext, and the tag, which leaves
  // 100 bytes for the plaintext.
  //
  static const size_t nonce_size (12);
  static const size_t tag_size (16);
  static const size_t plain_size (ticket_size - nonce_size - tag_size);

  static const uint8_t server_ticket_version (1);

  ticket_data ticket_sealer::
  seal (const server_ticket& t) const
  {
    LIBOBE_PRE (representable (t.issued) && representable (t.expires));

    // Serialize the plaintext.
    //
    array<uint8_t, plain_size> pt {}; // Zero padding.
    {
      packer p (pt);

      p.next (server_ticket_version);
      p.next (to_underlying (t.title));
      p.next (to_seconds (t.issued));
      p.next (to_seconds (t.expires));
      p.next (to_underlying (t.license));
      p.next (to_underlying (t.user));
      p.next (t.key);
    }

    // Encrypt it into the ticket after a random nonce.
    //
    ticket_data r;
    uint8_t* nonce (r.data ());
    uint8_t* ct (nonce + nonce_size);
    uint8_t* tag (ct + plain_size);

    if (RAND_bytes (nonce, static_cast<int> (nonce_size)) != 1)
      throw_crypto_error ("unable to generate nonce");

    cipher_ctx c (make_cipher_ctx ());

    int n;
    if (EVP_EncryptInit_ex (c.get (),
                            EVP_aes_256_gcm (),
                            nullptr /* engine */,
                            key_.data (),
                            nonce) != 1                                    ||
        EVP_EncryptUpdate (c.get (),
                           ct, &n,
                           pt.data (), static_cast<int> (pt.size ())) != 1 ||
        EVP_EncryptFinal_ex (c.get (), ct + n, &n) != 1                    ||
        EVP_CIPHER_CTX_ctrl (c.get (),
                             EVP_CTRL_GCM_GET_TAG,
                             static_cast<int> (tag_size),
                             tag) != 1)
      throw_crypto_error ("unable to seal ticket");

    return r;
  }

  server_ticket ticket_sealer::
  open (span<const uint8_t, ticket_size> d) const
  {
    const uint8_t* nonce (d.data ());
    const uint8_t* ct (nonce + nonce_size);
    const uint8_t* tag (ct + plain_size);

    // Decrypt and authenticate the plaintext.
    //
    array<uint8_t, plain_size> pt;
    {
      cipher_ctx c (make_cipher_ctx ());

      // Note that the tag is passed as non-const for historical reasons.
      //
      int n;
      if (EVP_DecryptInit_ex (c.get (),
                              EVP_aes_256_gcm (),
                              nullptr /* engine */,
                              key_.data (),
                              nonce) != 1                                   ||
          EVP_DecryptUpdate (c.get (),
                             pt.data (), &n,
                             ct, static_cast<int> (plain_size)) != 1        ||
          EVP_CIPHER_CTX_ctrl (c.get (),
                               EVP_CTRL_GCM_SET_TAG,
                               static_cast<int> (tag_size),
                               const_cast<uint8_t*> (tag)) != 1)
        throw_crypto_error ("unable to open ticket");

      // A finalization failure is an authentication failure, which is
      // invalid input rather than a library error.
      //
      if (EVP_DecryptFinal_ex (c.get (), pt.data () + n, &n) != 1)
      {
        ERR_clear_error ();
        throw invalid_input ("server ticket authentication failed");
      }
    }

    // Parse the plaintext.
    //
    unpacker u (pt);

    if (u.next<uint8_t> () != server_ticket_version)
      throw invalid_input ("unknown server ticket version");

    server_ticket r;
    r.title   = title_id {u.next<uint32_t> ()};
    r.issued  = from_seconds (u.next<uint32_t> ());
    r.expires = from_seconds (u.next<uint32_t> ());
    r.license = license_id {u.next<uint64_t> ()};
    r.user    = user_id {u.next<uint64_t> ()};

    const span<const uint8_t> k (u.next (r.key.size ()));
    copy (k.begin (), k.end (), r.key.begin ());

    return r;
  }
}
