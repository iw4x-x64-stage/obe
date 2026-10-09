// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service-storage.hxx>

using namespace std;

namespace obe
{
  storage_service::
  storage_service (file_store& s, storage_settings ss)
    : store_ (s),
      settings_ (move (ss))
  {
  }

  awaitable<void> storage_service::
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer& out)
  {
    in.next_uint8 (); // Reserved.

    const timestamp now (system_clock::now ());

    // Parse the file contents and verify their size.
    //
    // Note that the blob cannot be larger than what's left of the buffer,
    // which in turn is limited by the frame size. So we parse whatever is
    // there and then check the limit, which gives the client a meaningful
    // error.
    //
    auto contents = [this, &in] ()
    {
      bytes r (in.next_blob (in.remaining () / 8));

      if (r.size () > settings_.max_file_size)
        throw task_error (lsg_error::file_size_limit_exceeded,
                          "file of {} bytes exceeds {} bytes",
                          r.size (), settings_.max_file_size);

      return r;
    };

    // Parse the listing parameters that follow the owner and reply with the
    // owner's files.
    //
    // Note that a lambda cannot co_await on behalf of the enclosing
    // coroutine, so it returns the store's awaitable for us to co_await.
    //
    auto list = [this, &id, &in] (user_id owner)
    {
      const timestamp since (chrono::seconds (in.next_uint32 ()));
      const size_t limit (min<size_t> (in.next_uint16 (),
                                       settings_.max_results));

      string prefix;
      if (in.peek () == bit_type::string)
        prefix = in.next_string (file_header::max_name);

      if (owner != id.user && owner != publisher)
        throw task_error (lsg_error::permission_denied,
                          "files of user {} not accessible",
                          to_underlying (owner));

      return store_.list (id.title, owner, since, move (prefix), limit);
    };

    // Reply with the file headers.
    //
    auto headers = [&out] (const vector<file_header>& hs)
    {
      out.next_uint32 (static_cast<uint32_t> (hs.size ()));

      for (const file_header& h: hs)
      {
        out.next_uint32 (h.size);
        h.serialize (out);
      }
    };

    // The publisher files are only published by the server (see publish()),
    // so a user with the publisher's id (which no XUID is) cannot write.
    //
    if ((op == 1 || op == 2) && id.user == publisher)
      throw task_error (lsg_error::permission_denied,
                        "user {} cannot store files",
                        to_underlying (id.user));

    switch (op)
    {
      case 1:
      {
        array<bool, 2> fs;
        fs[0] = in.next_bool ();
        string n (in.next_string (file_header::max_name));
        fs[1] = in.next_bool ();
        bytes d (contents ());

        if (n.empty ())
          throw task_error (lsg_error::parameter_parse_error,
                            "empty file name");

        // Note that the store makes sure the user doesn't go over the limit
        // unless replacing an existing file.
        //
        const optional<file_header> h (
          co_await store_.upload (id.title,
                                  id.user,
                                  move (n),
                                  fs,
                                  move (d),
                                  now,
                                  settings_.max_files));

        if (!h)
          throw task_error (lsg_error::permission_denied,
                            "user has {} files",
                            settings_.max_files);

        // The client keeps the id to update the file with.
        //
        out.next_uint64 (to_underlying (h->id));
        break;
      }
      case 2:
      {
        const file_id f {in.next_uint64 ()};
        bytes d (contents ());

        // Note that the owner of a file never changes and the files are
        // never removed, so checking the owner before updating is not racy.
        //
        const optional<stored_file> sf (co_await store_.find (id.title, f));

        if (!sf)
          throw task_error (lsg_error::no_file,
                            "no file {}", to_underlying (f));

        if (sf->header.owner != id.user)
          throw task_error (lsg_error::permission_denied,
                            "file {} is owned by user {}",
                            to_underlying (f),
                            to_underlying (sf->header.owner));

        if (!co_await store_.update (id.title, f, move (d), now))
          throw task_error (lsg_error::no_file,
                            "no file {}", to_underlying (f));
        break;
      }
      case 5:
      {
        const file_id f {in.next_uint64 ()};

        const optional<stored_file> sf (co_await store_.find (id.title, f));

        if (!sf || (sf->header.owner != id.user &&
                    sf->header.owner != publisher))
          throw task_error (lsg_error::no_file,
                            "no file {}", to_underlying (f));

        out.next_uint32 (sf->header.size);
        sf->header.serialize (out);
        out.next_blob (sf->data);
        break;
      }
      case 7:
      {
        const user_id o {in.next_uint64 ()};
        headers (co_await list (o));
        break;
      }
      case 8:
      {
        headers (co_await list (publisher));
        break;
      }
      default:
        throw task_error (lsg_error::service_not_available,
                          "storage operation {} not supported", op);
    }
  }
}
