// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/service.hxx>
#include <libobe/performance-store.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct performance_settings
  {
    // The most values in a request.
    //
    size_t max_values = 64;
  };

  // The performance service (bdPerformance, service 17).
  //
  // The title uses it to keep a value per user and kind (for example, the
  // user's skill in a playlist) that the host looks up when picking the
  // players to migrate the game to. The operations are:
  //
  // 1 submit  The uint32 kind followed by the performance values to store.
  //           No results.
  //
  // 2 query   The uint32 kind followed by the uint64 user ids. Reply with
  //           uint32 count and the values of the users that have one.
  //
  // Note that any user can submit values for any other (the host submits
  // them for all the players).
  //
  // The values are kept in the store, which should outlive the service.
  //
  class LIBOBE_SYMEXPORT performance_service: public service
  {
  public:
    explicit
    performance_service (performance_store&, performance_settings = {});

    virtual kind_type
    kind () const noexcept override {return kind_type::bit;}

    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            bit_parser&,
            bit_serializer&) override;

  private:
    performance_store&         store_;
    const performance_settings settings_;
  };
}
