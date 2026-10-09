// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <compare> // strong_ordering

#include <libobe/types.hxx>

// The persistent classes of the PostgreSQL stores (see pgsql.hxx).
//
// This header is the input of the ODB compiler, which generates the
// database support code (model-odb.?xx) from it. In the consumption build
// the pregenerated support code is used (see buildfile for details), so any
// change to this header requires a development build to regenerate it.
//
// The classes mirror the store interfaces' types rather than being them so
// that the database representation is spelled out here and can evolve on
// its own. They are private to the library.
//
// Note that PostgreSQL has no unsigned integers so the unsigned values are
// stored in the signed columns of the same size, with the most significant
// bit in the sign bit (see the ODB manual, PostgreSQL Type Mapping). This
// is lossless and the ids are only compared for equality.

// The database schema versions.
//
// The base version is the oldest version the database can be migrated from
// and the current version is the one this code uses. While the current
// version is open, its changes are not yet released and are folded into it
// (see the ODB manual, Database Schema Evolution). Before releasing a new
// schema version, close it and once released bump the current version for
// the subsequent changes.
//
// The changelog (model.xml) records the released versions, which ODB uses
// to generate the migration statements. It is both the input and output of
// the ODB compiler and so is kept in the repository next to this header.
//
#define LIBOBE_SCHEMA_VERSION_BASE 1
#define LIBOBE_SCHEMA_VERSION      1, open

#pragma db model version(LIBOBE_SCHEMA_VERSION_BASE, LIBOBE_SCHEMA_VERSION)

namespace obe
{
  #pragma db value(bytes) type("BYTEA")

  // The stored file (see file_store).
  //
  // The name is unique within the title and the owner, which is also the
  // order of the lookups.
  //
  #pragma db object table("file") pointer(unique_ptr)
  class file_record
  {
  public:
    #pragma db id auto
    uint64_t id;

    uint32_t title;
    uint64_t owner;
    string   name;

    bool     flag1;
    bool     flag2;

    // Nanoseconds since the epoch (which fits until the year 2262).
    //
    int64_t  created;
    int64_t  modified;

    // The size of the data, so that it can be listed without loading the
    // data.
    //
    uint32_t size;

    bytes    data;

    #pragma db index("file_title_owner_name_i") \
      unique members(title, owner, name)
  };

  // The stored file without its data, for listing (see file_store).
  //
  #pragma db view object(file_record)
  struct file_record_header
  {
    uint64_t id;
    uint32_t title;
    uint64_t owner;
    string   name;
    bool     flag1;
    bool     flag2;
    int64_t  created;
    int64_t  modified;
    uint32_t size;
  };

  // The number of stored files.
  //
  #pragma db view object(file_record)
  struct file_record_count
  {
    #pragma db column("count(" + file_record::id + ")")
    uint64_t result;
  };

  // The performance value of the user for the title and kind (see
  // performance_store).
  //
  #pragma db value
  struct performance_key
  {
    uint32_t title;
    uint32_t kind;
    uint64_t user;

    friend std::strong_ordering
    operator<=> (const performance_key&, const performance_key&) = default;

    friend bool
    operator== (const performance_key&, const performance_key&) = default;
  };

  #pragma db object table("performance") pointer(unique_ptr)
  class performance_record
  {
  public:
    #pragma db id column("")
    performance_key id;

    int64_t value;
  };
}
