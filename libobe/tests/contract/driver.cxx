// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

// Check the postconditions and invariants as well, which are only checked
// at the audit level. Note that the level only affects the macros expanded
// in this file.
//
#define LIBOBE_CONTRACT 2

#include <string>
#include <print>
#include <csignal>   // signal(), SIGABRT
#include <cstdlib>   // _Exit()
#include <iostream>
#include <stdexcept> // invalid_argument, runtime_error

#include <libobe/contract.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

// The violation as thrown by the throwing handler.
//
struct violation
{
  contract_kind kind;
  string        expression;
  string        message;
};

static void
throwing_handler (const contract_violation& v)
{
  throw violation {v.kind,
                   v.expression != nullptr ? v.expression : "",
                   v.message != nullptr ? v.message : ""};
}

static void
returning_handler (const contract_violation&)
{
  println ("handled");
  cout.flush ();
}

// Exit with status 3 once the default reporter aborts the process, so that
// the test can check what the reporter printed.
//
extern "C" void
aborted (int)
{
  _Exit (3);
}

// The functions with the contracts that the cases violate.
//
static int
positive (int x)
{
  LIBOBE_PRE (x > 0);
  return x;
}

static int
positive_msg (int x)
{
  LIBOBE_PRE_MSG (x > 0, "x must be positive");
  return x;
}

static void
zero (int x)
{
  LIBOBE_ASSERT (x == 0);
}

static void
zero_msg (int x)
{
  LIBOBE_ASSERT_MSG (x == 0, "x must be zero");
}

static void
unreachable_code ()
{
  LIBOBE_UNREACHABLE ();
}

static int
increment (int x, int d, bool fail)
{
  int r (x);
  LIBOBE_POST (r > x);

  if (fail)
    throw runtime_error ("unwound");

  r += d;
  return r;
}

struct counter
{
  int value = 0;

  bool
  invariant () const noexcept {return value >= 0;}

  void
  add (int d, bool fail)
  {
    LIBOBE_INVARIANT (invariant ());

    value += d;

    if (fail)
      throw runtime_error ("unwound");
  }
};

// Usage: argv[0] [--report|--returning] <case>
//
// Violate the contract of the case and print the violation that the
// installed handler throws as:
//
// <kind> '<expression>'[: <message>]
//
// The cases are:
//
// pre, pre-msg              precondition (without and with the message)
// assert, assert-msg        assertion (without and with the message)
// unreachable               unreachable code
// post                      postcondition
// invariant-entry           invariant on entry
// invariant-exit            invariant on exit
//
// The case is printed as 'ok' if its contract holds and 'unwound' if it
// throws runtime_error, which the post-unwind and invariant-unwind cases do
// after breaking their postcondition and invariant. The pre-ok and post-ok
// cases satisfy their contracts.
//
// With --report no handler is installed and the default reporter prints
// the violation to stderr and aborts, in which case the driver exits with
// the status 3. With --returning the handler prints 'handled' to stdout and
// returns, and the default reporter does the rest.
//
int
main (int argc, char* argv[])
try
{
  string mode;
  string c;

  if (argc == 3)
  {
    mode = argv[1];
    c = argv[2];

    if (mode != "--report" && mode != "--returning")
      throw invalid_argument ("unknown option '" + mode + "'");
  }
  else if (argc == 2)
    c = argv[1];
  else
    throw invalid_argument ("case expected");

  // Install the handler, making sure the previous one is returned.
  //
  if (mode.empty () || mode == "--returning")
  {
    contract_handler h (mode.empty () ? &throwing_handler
                                      : &returning_handler);

    assert (set_contract_handler (h) == nullptr);
    assert (set_contract_handler (h) == h);
  }

  signal (SIGABRT, &aborted);

  // Violate the contract of the case.
  //
  try
  {
    if      (c == "pre")              positive (0);
    else if (c == "pre-ok")           positive (1);
    else if (c == "pre-msg")          positive_msg (0);
    else if (c == "assert")           zero (1);
    else if (c == "assert-msg")       zero_msg (1);
    else if (c == "unreachable")      unreachable_code ();
    else if (c == "post")             increment (1, 0, false);
    else if (c == "post-ok")          increment (1, 1, false);
    else if (c == "post-unwind")      increment (1, 0, true);
    else if (c == "invariant-entry")  counter {-1}.add (1, false);
    else if (c == "invariant-exit")   counter {}.add (-1, false);
    else if (c == "invariant-unwind") counter {}.add (-1, true);
    else
      throw invalid_argument ("unknown case '" + c + "'");

    println ("ok");
  }
  catch (const violation& v)
  {
    if (v.message.empty ())
      println ("{} '{}'", contract_kind_name (v.kind), v.expression);
    else
      println ("{} '{}': {}",
               contract_kind_name (v.kind), v.expression, v.message);
  }
  catch (const runtime_error& e)
  {
    println ("{}", e.what ());
  }
}
catch (const invalid_argument& e)
{
  println (cerr, "error: {}", e.what ());
  return 1;
}
