// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/frame-cipher.hxx>

#include <climits> // INT_MAX
#include <cstring> // memcpy()

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <libobe/tiger.hxx>
#include <libobe/openssl.hxx>

using namespace std;

namespace obe
{
  array<uint8_t, frame_cipher::block_size> frame_cipher::
  initial_vector (uint32_t seed)
  {
    tiger h;
    h.append (seed);

    array<uint8_t, block_size> r;
    memcpy (r.data (), h.binary (), r.size ());
    return r;
  }

  void frame_cipher::
  transform (uint32_t seed, span<uint8_t> d, bool e) const
  {
    LIBOBE_PRE (d.size () % block_size == 0);
    LIBOBE_PRE (d.size () <= INT_MAX);

    if (d.empty ())
      return;

    const array<uint8_t, block_size> iv (initial_vector (seed));

    cipher_ctx c (make_cipher_ctx ());

    if (EVP_CipherInit_ex (c.get (),
                           EVP_des_ede3_cbc (),
                           nullptr /* engine */,
                           key_.data (),
                           iv.data (),
                           e ? 1 : 0) != 1)
      throw_crypto_error ("unable to initialize cipher");

    // The data is always a whole number of blocks, so no padding.
    //
    EVP_CIPHER_CTX_set_padding (c.get (), 0);

    // Note that in-place operation is supported for the CBC mode.
    //
    int n;
    if (EVP_CipherUpdate (c.get (),
                          d.data (), &n,
                          d.data (), static_cast<int> (d.size ())) != 1)
      throw_crypto_error ("unable to transform data");

    LIBOBE_ASSERT (static_cast<size_t> (n) == d.size ());

    int f;
    if (EVP_CipherFinal_ex (c.get (), d.data () + n, &f) != 1)
      throw_crypto_error ("unable to finalize cipher");

    LIBOBE_ASSERT (f == 0);
  }

  void frame_cipher::
  encrypt (uint32_t seed, span<uint8_t> d) const
  {
    transform (seed, d, true);
  }

  void frame_cipher::
  decrypt (uint32_t seed, span<uint8_t> d) const
  {
    transform (seed, d, false);
  }

  frame_cipher::mac_type frame_cipher::
  authenticate (span<const uint8_t> d) const
  {
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int n;

    if (HMAC (EVP_sha1 (),
              key_.data (), static_cast<int> (key_.size ()),
              d.data (), d.size (),
              md, &n) == nullptr)
      throw_crypto_error ("unable to calculate HMAC");

    mac_type r;
    memcpy (r.data (), md, r.size ());
    return r;
  }
}
