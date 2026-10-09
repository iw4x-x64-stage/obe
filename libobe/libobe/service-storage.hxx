// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/service.hxx>
#include <libobe/file-store.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct storage_settings
  {
    // The largest file (the title's stats file is 8192 bytes).
    //
    size_t max_file_size = 0x10000;

    // The most files a user can have per title.
    //
    size_t max_files = 64;

    // The most headers a listing returns.
    //
    size_t max_results = 100;
  };

  // The storage service (bdStorage, service 10).
  //
  // All the requests start with a uchar8 0 (presumably reserved). The
  // operations are:
  //
  // 1 upload  bool flag, string name, bool flag, and blob contents (see
  //           file_header for the flags). Reply with the uint64 file id.
  //           Note: no result count (the client assumes one).
  //
  // 2 update  uint64 file id and blob contents. No results.
  //
  // 5 get     uint64 file id. Reply with uint32 size, the header, and the
  //           blob contents. Note: no result count (the client assumes
  //           one).
  //
  // 7 list    uint64 owner, uint32 minimum modification time, uint16
  //           maximum count, and optional string name prefix. Reply with
  //           uint32 count followed by, for each file, uint32 size and the
  //           header.
  //
  // 8 list    As above but without the owner, listing the title's
  //           publisher files (see publisher).
  //
  // The title keeps the player's stats in a file (mpdata): it lists the
  // player's own files (operation 7 with its own id), gets the stats file by
  // id, and, if there is none, starts with fresh stats. It then uploads them
  // the first time, keeping the returned id, and updates them by that id
  // after that.
  //
  // The title also fetches its playlists from a publisher file
  // (playlists.patch2, the playlistFilename dvar): it lists the publisher
  // files (operation 8), gets the file with that name by id, and parses
  // it. The client accepts playlists of up to 128KB, but the reply has to
  // fit its receive buffer (see lsg_server), which leaves a bit less than
  // 64KB. If there is no such file, the title has no playlists and retries
  // with a backoff.
  //
  // Note that the title never accesses other users' files, so the users can
  // only get and list their own and the publisher files. Note also that the
  // title treats any error (other than no stats file in the listing) as
  // fatal and drops to the main menu.
  //
  class LIBOBE_SYMEXPORT storage_service: public service
  {
  public:
    // The store should outlive the service.
    //
    explicit
    storage_service (file_store&, storage_settings = {});

    virtual kind_type
    kind () const noexcept override {return kind_type::bit;}

    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            bit_parser&,
            bit_serializer&) override;

  private:
    file_store&            store_;
    const storage_settings settings_;
  };
}
