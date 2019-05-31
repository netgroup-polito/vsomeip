//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#include <boost/predef.h>

#if (BOOST_OS_CYGWIN || BOOST_OS_WINDOWS)

#include <algorithm>
#include <iterator>
#include <string>
#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <boost/executable_path/detail/executable_path_internals.hpp>

#include <Windows.h>

namespace boost {
namespace detail {

boost::filesystem::path executable_path_worker()
{
  typedef std::vector<wchar_t> char_vector;
  typedef std::vector<wchar_t>::size_type size_type;
  boost::filesystem::path ret;
  char_vector buf(1024, 0);
  size_type size = buf.size();
  bool havePath = false;
  bool shouldContinue = true;
  do
  {
    DWORD result = GetModuleFileNameW(nullptr, buf.data(), size);
    DWORD lastError = GetLastError();
    if (result == 0)
    {
      shouldContinue = false;
    }
    else if (result < size)
    {
      havePath = true;
      shouldContinue = false;
    }
    else if (
      result == size && (lastError == ERROR_INSUFFICIENT_BUFFER || lastError == ERROR_SUCCESS))
    {
      size *= 2;
      buf.resize(size);
      std::fill(std::begin(buf), std::end(buf), 0);
    }
    else
    {
      shouldContinue = false;
    }
  } while (shouldContinue);
  if (!havePath)
  {
    return ret;
  }
  std::wstring pathString(buf.data());
  ret = pathString;
  return ret;
}
}
}

#endif
