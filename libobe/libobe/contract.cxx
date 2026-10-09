// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/contract.hxx>

#include <atomic>
#include <cstdio>  // fprintf(), fflush()
#include <cstdlib> // abort()

using namespace std;

namespace obe
{
  const char*
  contract_kind_name (contract_kind k) noexcept
  {
    switch (k)
    {
      case contract_kind::precondition:  return "precondition";
      case contract_kind::postcondition: return "postcondition";
      case contract_kind::invariant:     return "invariant";
      case contract_kind::assertion:     return "assertion";
      case contract_kind::unreachable:   return "unreachable";
    }

    return "contract";
  }

  namespace
  {
    atomic<contract_handler> current_handler {nullptr};

    const char*
    file_name (const char* p) noexcept
    {
      if (p == nullptr)
        return "<unknown>";

      const char* r (p);

      for (const char* i (p); *i != '\0'; ++i)
      {
        if (*i == '/' || *i == '\\')
          r = i + 1;
      }

      return r;
    }

    void
    report (const contract_violation& v) noexcept
    {
      const char* f  (file_name (v.file));
      const char* fn (v.function   != nullptr ? v.function   : "<unknown>");
      const char* e  (v.expression != nullptr ? v.expression : "<unknown>");

      switch (v.kind)
      {
        case contract_kind::precondition:
        case contract_kind::postcondition:
        case contract_kind::invariant:
          fprintf (stderr,
                   "%s:%u: error: %s violated: %s\n",
                   f, v.line, contract_kind_name (v.kind), e);
          break;

        case contract_kind::assertion:
          fprintf (stderr,
                   "%s:%u: error: assertion failed: %s\n",
                   f, v.line, e);
          break;

        case contract_kind::unreachable:
          fprintf (stderr,
                   "%s:%u: error: control reached unreachable code\n",
                   f, v.line);
          break;
      }

      fprintf (stderr, "%s:%u: note: in '%s'\n", f, v.line, fn);

      if (v.message != nullptr)
        fprintf (stderr, "%s:%u: note: %s\n", f, v.line, v.message);

      fflush (stderr);
    }
  }

  contract_handler
  set_contract_handler (contract_handler h) noexcept
  {
    // We only care that a failure sees either the old handler or the
    // new one. There is no other state being transferred through this
    // atomic, so relaxed ordering is sufficient.
    //
    // Note also that returning the old value is useful for the usual
    // temporary-handler case.
    //
    return current_handler.exchange (h, memory_order_relaxed);
  }

  [[noreturn]] void
  contract_fail (contract_kind k,
                 const char* file,
                 unsigned line,
                 const char* function,
                 const char* expression,
                 const char* message) noexcept (false)
  {
    const contract_violation v {file, function, expression, message, line, k};

    // The slightly unusual part here is that a handler is allowed to
    // throw. This is primarily useful for tests which need to verify a
    // contract without terminating the test process. This is also why
    // contract_fail() is noexcept(false), in spite of never returning
    // normally.
    //
    // If the handler returns, then nothing has changed as far as the
    // failed contract is concerned. We cannot resume execution past it,
    // so continue with the normal reporting path and terminate.
    //
    if (contract_handler h = current_handler.load (memory_order_relaxed))
      h (v);

    report (v), abort ();
  }
}
