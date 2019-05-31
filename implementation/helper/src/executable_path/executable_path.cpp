//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#include <string>

#include <boost/predef.h>

#include <boost/executable_path/executable_path.hpp>
#include <boost/executable_path/detail/executable_path_internals.hpp>

namespace boost {

std::string executable_path(const char* argv0)
{
  boost::filesystem::path ret = detail::executable_path_worker();
  if (ret.empty())
  {
    ret = detail::executable_path_fallback(argv0);
  }
  return ret.make_preferred().string();
}

std::wstring executable_path(const wchar_t* argv0)
{
  boost::filesystem::path ret = detail::executable_path_worker();
  if (ret.empty())
  {
    ret = detail::executable_path_fallback(argv0);
  }
  return ret.make_preferred().wstring();
}
}
