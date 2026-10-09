// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <map>

#include <boost/asio/awaitable.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>

#include <libobe/export.hxx>

namespace obe
{
  using boost::asio::awaitable;

  enum class file_id: uint64_t {};

  // The stored file's header (bdLobbyFileHeader):
  //
  // uint64  file id
  // uint32  creation time       (seconds since the UNIX epoch)
  // uint32  modification time   (seconds since the UNIX epoch)
  // bool    flag
  // bool    flag
  // uint64  owner
  // string  name
  //
  // Note that the size is not part of the serialized header: where the
  // client expects it, it precedes the header as uint32.
  //
  // The flags are passed by the client on upload and are echoed back as
  // is. In the client they are two enumerations (with 2 as the unset value)
  // that it converts to and from the bools by comparing with 1, but this
  // title never reads them back and always uploads with the first flag clear
  // and the second set. So their meaning doesn't matter to us and is not
  // known (the enumerator names are not in the binary).
  //
  struct LIBOBE_SYMEXPORT file_header
  {
    // The longest name (the client stores 128 characters including the
    // terminating '\0').
    //
    static constexpr size_t max_name = 127;

    file_id          id {};
    timestamp        created;
    timestamp        modified;
    array<bool, 2>   flags {};
    user_id          owner {};
    string           name;
    uint32_t         size = 0;

    // Serialize the header. The times must be representable as uint32
    // seconds.
    //
    void
    serialize (bit_serializer&) const;
  };

  struct stored_file
  {
    file_header header;
    bytes       data;
  };

  // The file storage (for the storage service).
  //
  // The files belong to a title and an owner and are identified by the id
  // assigned by the store when they are created. Within the title and the
  // owner, the names are unique.
  //
  // The operations are coroutines that run on the caller's executor (the
  // io_context thread; see service for details). An implementation that does
  // blocking IO (for example, a database) performs it on another thread and
  // resumes the caller once done. Each operation is atomic. On failure (for
  // example, if the database is unavailable) an operation throws task_error
  // (normally with lsg_error::service_not_available), which the gateway
  // replies with.
  //
  class LIBOBE_SYMEXPORT file_store
  {
  public:
    // Return the file or nullopt if there is no such file for the title.
    //
    virtual awaitable<optional<stored_file>>
    find (title_id, file_id) = 0;

    // Return the headers of the title's files, ordered by id, of the owner
    // (any if nullopt) that were modified at or after the specified time
    // and whose name starts with the prefix, but no more than the specified
    // number.
    //
    virtual awaitable<vector<file_header>>
    list (title_id,
          optional<user_id> owner,
          timestamp since,
          string prefix,
          size_t limit) = 0;

    // Create the file or, if the owner already has a file with this name,
    // replace its contents and flags. Return its header or nullopt if the
    // file would be created but the owner already has the specified number
    // of files.
    //
    // The name must not be empty or longer than file_header::max_name.
    //
    virtual awaitable<optional<file_header>>
    upload (title_id,
            user_id owner,
            string name,
            array<bool, 2> flags,
            bytes data,
            timestamp now,
            size_t limit) = 0;

    // Replace the file's contents. Return its header or nullopt if there is
    // no such file for the title.
    //
    virtual awaitable<optional<file_header>>
    update (title_id, file_id, bytes data, timestamp now) = 0;

    file_store () = default;

    virtual
    ~file_store ();

    file_store (const file_store&) = delete;
    file_store& operator= (const file_store&) = delete;
  };

  // The file store that keeps the files in memory, for development and
  // testing.
  //
  class LIBOBE_SYMEXPORT memory_file_store: public file_store
  {
  public:
    virtual awaitable<optional<stored_file>>
    find (title_id, file_id) override;

    virtual awaitable<vector<file_header>>
    list (title_id,
          optional<user_id>,
          timestamp,
          string,
          size_t) override;

    virtual awaitable<optional<file_header>>
    upload (title_id,
            user_id,
            string,
            array<bool, 2>,
            bytes,
            timestamp,
            size_t) override;

    virtual awaitable<optional<file_header>>
    update (title_id, file_id, bytes, timestamp) override;

  private:
    struct entry
    {
      title_id    title;
      stored_file file;
    };

    std::map<file_id, entry> files_;
    uint64_t                 last_id_ = 0;
  };
}
