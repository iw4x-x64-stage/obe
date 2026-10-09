// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/lsg-registry.hxx>

using namespace std;

namespace obe
{
  // lsg_registry::registration
  //
  lsg_registry::registration::
  registration (lsg_registry& r, const lsg_identity& id)
    : registry_ (&r),
      title_ (id.title),
      user_ (id.user),
      connection_ (id.connection)
  {
  }

  lsg_registry::registration::
  registration (registration&& r) noexcept
    : registry_ (r.registry_),
      title_ (r.title_),
      user_ (r.user_),
      connection_ (r.connection_)
  {
    r.registry_ = nullptr;
  }

  lsg_registry::registration& lsg_registry::registration::
  operator= (registration&& r) noexcept
  {
    if (this != &r)
    {
      reset ();

      registry_ = r.registry_;
      title_ = r.title_;
      user_ = r.user_;
      connection_ = r.connection_;

      r.registry_ = nullptr;
    }

    return *this;
  }

  lsg_registry::registration::
  ~registration ()
  {
    reset ();
  }

  void lsg_registry::registration::
  reset () noexcept
  {
    if (registry_ != nullptr)
    {
      registry_->detach (title_, user_, connection_);
      registry_ = nullptr;
    }
  }

  // lsg_registry
  //
  lsg_registry::registration lsg_registry::
  attach (const lsg_identity& id, sink s)
  {
    LIBOBE_PRE (s != nullptr);

    [[maybe_unused]] const bool inserted (
      sinks_[key (id.title, id.user)].emplace (id.connection,
                                               move (s)).second);

    LIBOBE_PRE_MSG (inserted, "duplicate connection id");

    return registration (*this, id);
  }

  size_t lsg_registry::
  push (title_id t, user_id u, const bytes& p)
  {
    auto i (sinks_.find (key (t, u)));
    if (i == sinks_.end ())
      return 0;

    size_t r (0);
    for (auto& [c, s]: i->second)
    {
      if (s (p))
        ++r;
    }

    return r;
  }

  void lsg_registry::
  detach (title_id t, user_id u, uint64_t c) noexcept
  {
    auto i (sinks_.find (key (t, u)));
    if (i == sinks_.end ())
      return;

    i->second.erase (c);

    if (i->second.empty ())
      sinks_.erase (i);
  }
}
