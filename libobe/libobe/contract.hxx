// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <concepts>
#include <exception> // uncaught_exceptions()
#include <utility>   // move()

#include <libobe/export.hxx>

// Contract checking.
//
// A precondition describes a requirement imposed on a caller. An assertion
// describes a property established by the implementation. Postconditions and
// invariants are audit checks since they normally evaluate code on both entry
// and exit.
//
// The checking level is selected with LIBOBE_CONTRACT:
//
//   0  off      preconditions are omitted and internal assertions become
//               optimizer assumptions
//   1  default  preconditions, assertions, and unreachability are checked
//   2  audit    postconditions and invariants are checked as well
//
#define LIBOBE_CONTRACT_OFF     0
#define LIBOBE_CONTRACT_DEFAULT 1
#define LIBOBE_CONTRACT_AUDIT   2

#ifndef LIBOBE_CONTRACT
#  define LIBOBE_CONTRACT LIBOBE_CONTRACT_DEFAULT
#endif

namespace obe
{
  enum class contract_kind: unsigned char
  {
    precondition,
    postcondition,
    invariant,
    assertion,
    unreachable
  };

  LIBOBE_SYMEXPORT const char*
  contract_kind_name (contract_kind) noexcept;

  struct contract_violation
  {
    const char*   file;
    const char*   function;
    const char*   expression;
    const char*   message;
    unsigned      line;
    contract_kind kind;
  };

  // Report a violated contract.
  //
  // The installed handler is called first. It may throw, which is
  // useful for tests. Returning from the handler does not discharge the
  // violation: the default reporter is run and the process is
  // terminated.
  //
  [[noreturn]] LIBOBE_SYMEXPORT void
  contract_fail (contract_kind,
                 const char* file,
                 unsigned line,
                 const char* function,
                 const char* expression,
                 const char* message = nullptr) noexcept (false);

  using contract_handler = void (*) (const contract_violation&);

  // Install a process-wide contract handler and return the previous
  // handler. Passing nullptr restores the default behavior.
  //
  LIBOBE_SYMEXPORT contract_handler
  set_contract_handler (contract_handler) noexcept;

  template <typename F>
  concept contract_predicate = requires (F& f)
  {
    { f () } -> std::convertible_to<bool>;
  };

  // Check a postcondition when the scope is left normally.
  //
  template <contract_predicate F>
  class postcondition_guard
  {
  public:
    postcondition_guard (F p,
                         const char* f,
                         unsigned l,
                         const char* fn,
                         const char* e)
      : predicate_  (std::move (p)),
        file_       (f),
        function_   (fn),
        expression_ (e),
        line_       (l),
        uncaught_   (std::uncaught_exceptions ())
    {
      // So there is nothing to check at this point. The expression
      // describes the state after the operation and evaluating it here
      // would just give us the state at the point where
      // LIBOBE_POST() was written.
      //
      // Instead we keep the predicate and evaluate it from the
      // destructor. In practice this will normally be the lambda
      // produced by the macro below, capturing the surrounding scope by
      // reference. This is also why the guard has to stay in that
      // scope.
      //
      // Note that the referenced locals declared before the guard are
      // still alive when its destructor runs (block locals are
      // destroyed in reverse declaration order), so the predicate can
      // inspect their final values.
      //
      // We also remember the exception count here. We will use it below
      // to tell normal scope exit from stack unwinding.
      //
    }

    ~postcondition_guard () noexcept (false)
    {
      // A postcondition only says something about successful
      // completion. If an exception appeared since construction, then
      // we are unwinding and there is no completed operation to check.
      //
      if (std::uncaught_exceptions () != uncaught_)
        return;

      // This is the point at which we finally evaluate the expression.
      // So any changes made after the LIBOBE_POST() declaration are
      // visible here.
      //
      if (!static_cast<bool> (predicate_ ()))
        contract_fail (contract_kind::postcondition,
                       file_,
                       line_,
                       function_,
                       expression_);
    }

    // There should only ever be one guard for one LIBOBE_POST()
    // declaration. A copy would end up checking the same postcondition
    // again when the copy is destroyed.
    //
    postcondition_guard (const postcondition_guard&) = delete;
    postcondition_guard& operator= (const postcondition_guard&) = delete;

  private:
    F           predicate_;
    const char* file_;
    const char* function_;
    const char* expression_;
    unsigned    line_;
    int         uncaught_;
  };

  // Check a class invariant on entry and on successful scope exit.
  //
  template <contract_predicate F>
  class invariant_guard
  {
  public:
    invariant_guard (F p,
                     const char* f,
                     unsigned l,
                     const char* fn,
                     const char* e)
      : predicate_  (std::move (p)),
        file_       (f),
        function_   (fn),
        expression_ (e),
        line_       (l),
        uncaught_   (std::uncaught_exceptions ())
    {
      // Unlike a postcondition, an invariant has something useful to
      // say at this point. Check it before the operation gets a chance
      // to change the object.
      //
      // Note that if this fails then construction of the guard never
      // completes. So there will be no destructor call and, in
      // particular, no second report saying the same invariant failed
      // on exit.
      //
      if (!static_cast<bool> (predicate_ ()))
        contract_fail (contract_kind::invariant,
                       file_,
                       line_,
                       function_,
                       expression_,
                       "on entry");
    }

    ~invariant_guard () noexcept (false)
    {
      // During the operation the object may quite legitimately pass
      // through a state in which its invariant doesn't hold. If the
      // operation throws, then destruction of this guard happens on
      // that path and checking the intermediate state would be
      // misleading. So leave the original exception alone.
      //
      if (std::uncaught_exceptions () != uncaught_)
        return;

      // Normal return means the operation had a chance to put the
      // object back into an invariant-preserving state, so check the
      // same predicate once more.
      //
      if (!static_cast<bool> (predicate_ ()))
        contract_fail (contract_kind::invariant,
                       file_,
                       line_,
                       function_,
                       expression_,
                       "on exit");
    }

    // Same story as for postcondition_guard: copying this object would
    // create another exit check that wasn't present in the source.
    //
    invariant_guard (const invariant_guard&) = delete;
    invariant_guard& operator= (const invariant_guard&) = delete;

  private:
    F           predicate_;
    const char* file_;
    const char* function_;
    const char* expression_;
    unsigned    line_;
    int         uncaught_;
  };
}

// In an unchecked build we still want internal assertions to describe
// facts to the optimizer. Unfortunately there isn't one spelling for
// this across the compilers we support, so hide the compiler-specific
// part here.
//
// Note that assertion expressions must be free of side effects.
// Depending on the compiler this expression may stop behaving like an
// ordinary runtime expression once it reaches one of these intrinsics.
//
#if defined(__clang__)

#  define LIBOBE_CONTRACT_ASSUME_(e) __builtin_assume (e)

#elif defined(_MSC_VER)

#  define LIBOBE_CONTRACT_ASSUME_(e) __assume (e)

#elif defined(__GNUC__)

     // GCC doesn't give us the same primitive on all supported
     // versions. So express the assumption by making the false branch
     // unreachable. This gives the optimizer the information we need
     // after the branch.
     //
#  define LIBOBE_CONTRACT_ASSUME_(e)                                           \
     do                                                                        \
     {                                                                         \
       if (!(e))                                                               \
         __builtin_unreachable ();                                             \
     }                                                                         \
     while (false)

#else

     // No useful compiler primitive here. Keep the expression
     // unevaluated so we at least still type-check it without
     // introducing a runtime check.
     //
#  define LIBOBE_CONTRACT_ASSUME_(e) static_cast<void> (sizeof (e))

#endif

// Same idea for a point that is unconditionally unreachable.
//
#if defined(__clang__) || defined(__GNUC__)

#  define LIBOBE_CONTRACT_UNREACHABLE_() __builtin_unreachable ()

#elif defined(_MSC_VER)

#  define LIBOBE_CONTRACT_UNREACHABLE_() __assume (0)

#else

#  define LIBOBE_CONTRACT_UNREACHABLE_() static_cast<void> (0)

#endif

// We need the extra expansion step here so something like __LINE__ is
// expanded before it is pasted into the resulting identifier.
//
#define LIBOBE_CONTRACT_CAT_(x, y) x##y
#define LIBOBE_CONTRACT_CAT(x, y)  LIBOBE_CONTRACT_CAT_ (x, y)

// This is the common path for contracts that can be checked
// immediately. Keep it as an expression so the public macros work
// naturally anywhere a void expression would.
//
// Stringizing e here also means contract_fail() gets the expression as
// it appeared at the call site without each public macro having to
// repeat this machinery.
//
#define LIBOBE_CONTRACT_CHECK_(k, e, m)                                        \
  (static_cast<bool> (e)                                                       \
   ? void ()                                                                   \
   : ::obe::contract_fail ((k),                                                \
                           __FILE__,                                           \
                           __LINE__,                                           \
                           __func__,                                           \
                           #e,                                                 \
                           (m)))

#if LIBOBE_CONTRACT >= LIBOBE_CONTRACT_DEFAULT

#  define LIBOBE_PRE(e)                                                        \
     LIBOBE_CONTRACT_CHECK_ (::obe::contract_kind::precondition,               \
                              e,                                               \
                              nullptr)

#  define LIBOBE_PRE_MSG(e, m)                                                 \
     LIBOBE_CONTRACT_CHECK_ (::obe::contract_kind::precondition,               \
                              e,                                               \
                              m)

#  define LIBOBE_ASSERT(e)                                                     \
     LIBOBE_CONTRACT_CHECK_ (::obe::contract_kind::assertion,                  \
                              e,                                               \
                              nullptr)

#  define LIBOBE_ASSERT_MSG(e, m)                                              \
     LIBOBE_CONTRACT_CHECK_ (::obe::contract_kind::assertion,                  \
                              e,                                               \
                              m)

     // There is no expression to test in this case. Getting here is the
     // failure, so use a fixed expression string for the diagnostic.
     //
#  define LIBOBE_UNREACHABLE()                                                 \
     ::obe::contract_fail (::obe::contract_kind::unreachable,                  \
                           __FILE__,                                           \
                           __LINE__,                                           \
                           __func__,                                           \
                           "control reached this point")

#else

// Preconditions describe requirements on callers, so in the off
// configuration we simply don't evaluate them. Turning one into an
// optimizer assumption would let bad external input make the program
// undefined.
//
// This also means a precondition expression cannot be relied on for
// side effects.
//
#  define LIBOBE_PRE(e)        static_cast<void> (0)
#  define LIBOBE_PRE_MSG(e, m) static_cast<void> (0)

// Assertions are different in this respect. They describe facts
// established by our own implementation, so those facts are still
// useful to the optimizer once runtime checking is disabled.
//
// As mentioned above, this relies on e having no side effects.
//
#  define LIBOBE_ASSERT(e)    \
     LIBOBE_CONTRACT_ASSUME_ (static_cast<bool> (e))

#  define LIBOBE_ASSERT_MSG(e, m)    \
     LIBOBE_CONTRACT_ASSUME_ (static_cast<bool> (e))

#  define LIBOBE_UNREACHABLE() LIBOBE_CONTRACT_UNREACHABLE_ ()

#endif

#if LIBOBE_CONTRACT >= LIBOBE_CONTRACT_AUDIT

     // We can't evaluate a postcondition here since this is still the
     // point at which it is declared. So wrap the expression in a
     // lambda and let the guard above evaluate it when the scope exits.
     //
     // The reference capture is intentional. We want the expression to
     // see the values at the end of the operation, not copies made
     // here.
     //
     // Note that this relies on anything referenced by e being alive
     // when the guard is destroyed. For ordinary locals declared before
     // LIBOBE_POST(), reverse destruction order gives us exactly
     // that.
     //
     // Finally, use __LINE__ to give the otherwise unnamed guard a
     // local name. Two such declarations on the same source line will
     // collide, which seems like a reasonable restriction for this
     // macro.
     //
#  define LIBOBE_POST(e)                                                       \
     ::obe::postcondition_guard                                                \
       LIBOBE_CONTRACT_CAT (libobe_postcondition_, __LINE__) (                 \
         [&] () -> bool {return static_cast<bool> (e);},                       \
         __FILE__,                                                             \
         __LINE__,                                                             \
         __func__,                                                             \
         #e)

     // Same mechanism for invariants. The difference is in
     // invariant_guard, which evaluates the predicate once during
     // construction and once again on normal scope exit.
     //
#  define LIBOBE_INVARIANT(e)                                                  \
     ::obe::invariant_guard                                                    \
       LIBOBE_CONTRACT_CAT (libobe_invariant_, __LINE__) (                     \
         [&] () -> bool {return static_cast<bool> (e);},                       \
         __FILE__,                                                             \
         __LINE__,                                                             \
         __func__,                                                             \
         #e)

#else

// Audit expressions disappear at the lower checking levels, so they
// have the same side-effect restriction as the other contract
// expressions.
//
#  define LIBOBE_POST(e)      static_cast<void> (0)
#  define LIBOBE_INVARIANT(e) static_cast<void> (0)

#endif
