#pragma once

#include <iosfwd>
#include <string>

#include <libobe/apache/export.hxx>

namespace obe_apache
{
  // Print a greeting for the specified name into the specified
  // stream. Throw std::invalid_argument if the name is empty.
  //
  LIBOBE_APACHE_SYMEXPORT void
  say_hello (std::ostream&, const std::string& name);
}
