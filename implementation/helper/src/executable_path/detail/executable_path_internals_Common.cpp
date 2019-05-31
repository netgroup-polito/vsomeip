//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <locale>
#include <iterator>
#include <string>
#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/locale.hpp>
#include <boost/predef.h>
#include <boost/version.hpp>
#include <boost/tokenizer.hpp>

#if (BOOST_VERSION > BOOST_VERSION_NUMBER(1, 64, 0))
#  include <boost/process.hpp>
#endif

#if (BOOST_OS_CYGWIN || BOOST_OS_WINDOWS)
#  include <Windows.h>
#endif

#include <boost/executable_path/detail/executable_path_internals.hpp>

namespace boost { namespace detail {

std::string os_pathsep()
{
#if (BOOST_OS_WINDOWS)
  return ";";
#else
  return ":";
#endif
}

std::wstring wos_pathsep()
{
#if (BOOST_OS_WINDOWS)
  return L";";
#else
  return L":";
#endif
}

std::string os_sep()
{
#if (BOOST_OS_WINDOWS)
  return "\\";
#else
  return "/";
#endif
}

std::wstring wos_sep()
{
#if (BOOST_OS_WINDOWS)
  return L"\\";
#else
  return L"/";
#endif
}

bool IsUTF8(const std::locale& loc)
{
  std::string locName = loc.name();
  if (!locName.empty() && std::string::npos != locName.find("UTF-8"))
  {
    return true;
  }
  return false;
}

std::string to_string(const std::wstring& s, const std::locale& loc)
{
  typedef std::vector<char> char_vector;
  typedef std::codecvt<wchar_t, char, std::mbstate_t> converter_type;
  typedef std::ctype<wchar_t> wchar_facet;
  std::string return_value;
  if (s.empty())
  {
    return "";
  }
  if (IsUTF8(loc))
  {
    return_value = boost::locale::conv::utf_to_utf<char>(s);
    if (!return_value.empty())
    {
      return return_value;
    }
  }
  const wchar_t* from = s.c_str();
  size_t len = s.length();
  size_t converterMaxLength = 6;
  size_t bufferSize = ((len + 6) * converterMaxLength);
  if (std::has_facet<converter_type>(loc))
  {
    const converter_type& converter = std::use_facet<converter_type>(loc);
    if (false == converter.always_noconv())
    {
      converterMaxLength = converter.max_length();
      if (6 != converterMaxLength)
      {
        bufferSize = ((len + 6) * converterMaxLength);
      }
      std::mbstate_t state;
      const wchar_t* from_next = nullptr;
      char_vector to(bufferSize, 0);
      char* toPtr = to.data();
      char* to_next = nullptr;
      const converter_type::result result
        = converter.out(state, from, from + len, from_next, toPtr, toPtr + bufferSize, to_next);
      if ((converter_type::ok == result || converter_type::noconv == result) && 0 != toPtr[0])
      {
        return_value.assign(toPtr, to_next);
      }
    }
  }
  if (return_value.empty() && std::has_facet<wchar_facet>(loc))
  {
    char_vector to(bufferSize, 0);
    auto toPtr = to.data();
    const wchar_facet& facet = std::use_facet<wchar_facet>(loc);
    if (facet.narrow(from, from + len, '?', toPtr) != nullptr)
    {
      return_value = toPtr;
    }
  }
  return return_value;
}

std::wstring to_wstring(const std::string& s, const std::locale& loc)
{
  typedef std::vector<wchar_t> wchar_vector;
  typedef std::ctype<wchar_t> wchar_facet;
  std::wstring return_value;
  if (s.empty())
  {
    return L"";
  }
  if (IsUTF8(loc))
  {
    return_value = boost::locale::conv::utf_to_utf<wchar_t>(s);
    if (!return_value.empty())
    {
      return return_value;
    }
  }
  if (std::has_facet<wchar_facet>(loc))
  {
    std::string::size_type bufferSize = s.size() + 2;
    wchar_vector to(bufferSize, 0);
    wchar_t* toPtr = to.data();
    const wchar_facet& facet = std::use_facet<wchar_facet>(loc);
    if (facet.widen(s.c_str(), s.c_str() + s.size(), toPtr) != nullptr)
    {
      return_value = toPtr;
    }
  }
  return return_value;
}

std::string GetEnv(const std::string& varName)
{
  if (varName.empty()) return "";
#if (BOOST_OS_BSD || BOOST_OS_CYGWIN || BOOST_OS_LINUX || BOOST_OS_MACOS || BOOST_OS_SOLARIS)
  char* value = std::getenv(varName.c_str());
  if (!value) return "";
  return value;
#elif (BOOST_OS_WINDOWS)
  typedef std::vector<char> char_vector;
  typedef std::vector<char>::size_type size_type;
  char_vector value(8192, 0);
  size_type size = value.size();
  bool haveValue = false;
  bool shouldContinue = true;
  do
  {
    DWORD result = GetEnvironmentVariableA(varName.c_str(), value.data(), size);
    if (result == 0)
    {
      shouldContinue = false;
    }
    else if (result < size)
    {
      haveValue = true;
      shouldContinue = false;
    }
    else
    {
      size *= 2;
      value.resize(size);
    }
  } while (shouldContinue);
  std::string ret;
  if (haveValue)
  {
    ret = value.data();
  }
  return ret;
#else
  return "";
#endif
}

std::wstring GetEnv(const std::wstring& varName)
{
  if (varName.empty()) return L"";
#if (BOOST_OS_BSD || BOOST_OS_CYGWIN || BOOST_OS_LINUX || BOOST_OS_MACOS || BOOST_OS_SOLARIS)
  std::locale loc;
  std::string sVarName = to_string(varName, loc);
  char* value = std::getenv(sVarName.c_str());
  if (!value) return L"";
  std::wstring ret = to_wstring(value, loc);
  return ret;
#elif (BOOST_OS_WINDOWS)
  typedef std::vector<wchar_t> char_vector;
  typedef std::vector<wchar_t>::size_type size_type;
  char_vector value(8192, 0);
  size_type size = value.size();
  bool haveValue = false;
  bool shouldContinue = true;
  do
  {
    DWORD result = GetEnvironmentVariableW(varName.c_str(), value.data(), size);
    if (result == 0)
    {
      shouldContinue = false;
    }
    else if (result < size)
    {
      haveValue = true;
      shouldContinue = false;
    }
    else
    {
      size *= 2;
      value.resize(size);
    }
  } while (shouldContinue);
  std::wstring ret;
  if (haveValue)
  {
    ret = value.data();
  }
  return ret;
#else
  return L"";
#endif
}

bool GetDirectoryListFromDelimitedString(const std::string& str, std::vector<std::string>& dirs)
{
  typedef boost::char_separator<char> char_separator_type;
  typedef boost::tokenizer<boost::char_separator<char>, std::string::const_iterator, std::string>
    tokenizer_type;
  dirs.clear();
  if (str.empty())
  {
    return false;
  }
  char_separator_type pathSep(os_pathsep().c_str());
  tokenizer_type strTok(str, pathSep);
  typename tokenizer_type::iterator strIt;
  typename tokenizer_type::iterator strEndIt = strTok.end();
  for (strIt = strTok.begin(); strIt != strEndIt; ++strIt)
  {
    dirs.push_back(*strIt);
  }
  if (dirs.empty())
  {
    return false;
  }
  return true;
}

bool GetDirectoryListFromDelimitedString(const std::wstring& str, std::vector<std::wstring>& dirs)
{
  typedef boost::char_separator<wchar_t> char_separator_type;
  typedef boost::tokenizer<
    boost::char_separator<wchar_t>, std::wstring::const_iterator, std::wstring>
    tokenizer_type;
  dirs.clear();
  if (str.empty())
  {
    return false;
  }
  char_separator_type pathSep(wos_pathsep().c_str());
  tokenizer_type strTok(str, pathSep);
  typename tokenizer_type::iterator strIt;
  typename tokenizer_type::iterator strEndIt = strTok.end();
  for (strIt = strTok.begin(); strIt != strEndIt; ++strIt)
  {
    dirs.push_back(*strIt);
  }
  if (dirs.empty())
  {
    return false;
  }
  return true;
}

std::string search_path(const std::string& file)
{
  if (file.empty()) return "";
  std::string ret;
#if (BOOST_VERSION > BOOST_VERSION_NUMBER(1, 64, 0))
  {
    namespace bp = boost::process;
    boost::filesystem::path p = bp::search_path(file);
    ret = p.make_preferred().string();
  }
#endif
  if (!ret.empty()) return ret;
  // Drat! I have to do it the hard way.
  std::string pathEnvVar = GetEnv("PATH");
  if (pathEnvVar.empty()) return "";
  std::vector<std::string> pathDirs;
  bool getDirList = GetDirectoryListFromDelimitedString(pathEnvVar, pathDirs);
  if (!getDirList) return "";
  std::vector<std::string>::const_iterator it = pathDirs.cbegin();
  std::vector<std::string>::const_iterator itEnd = pathDirs.cend();
  for (; it != itEnd; ++it)
  {
    boost::filesystem::path p(*it);
    p /= file;
    if (boost::filesystem::exists(p) && boost::filesystem::is_regular_file(p))
    {
      return p.make_preferred().string();
    }
  }
  return "";
}

std::wstring search_path(const std::wstring& file)
{
  if (file.empty()) return L"";
  std::wstring ret;
#if (BOOST_VERSION > BOOST_VERSION_NUMBER(1, 64, 0))
  {
    namespace bp = boost::process;
    boost::filesystem::path p = bp::search_path(file);
    ret = p.make_preferred().string();
  }
#endif
  if (!ret.empty()) return ret;
  // Drat! I have to do it the hard way.
  std::wstring pathEnvVar = GetEnv(L"PATH");
  if (pathEnvVar.empty()) return L"";
  std::vector<std::wstring> pathDirs;
  bool getDirList = GetDirectoryListFromDelimitedString(pathEnvVar, pathDirs);
  if (!getDirList) return L"";
  std::vector<std::wstring>::const_iterator it = pathDirs.cbegin();
  std::vector<std::wstring>::const_iterator itEnd = pathDirs.cend();
  for (; it != itEnd; ++it)
  {
    boost::filesystem::path p(*it);
    p /= file;
    if (boost::filesystem::exists(p) && boost::filesystem::is_regular_file(p))
    {
      return p.make_preferred().wstring();
    }
  }
  return L"";
}

std::string executable_path_fallback(const char* argv0)
{
  if (argv0 == nullptr) return "";
  if (argv0[0] == 0) return "";
  if (strstr(argv0, os_sep().c_str()) != nullptr)
  {
    boost::system::error_code ec;
    boost::filesystem::path p(
      boost::filesystem::canonical(argv0, boost::filesystem::current_path(), ec));
    if (ec.value() == boost::system::errc::success)
    {
      return p.make_preferred().string();
    }
  }
  std::string ret = search_path(argv0);
  if (!ret.empty())
  {
    return ret;
  }
  boost::system::error_code ec;
  boost::filesystem::path p(
    boost::filesystem::canonical(argv0, boost::filesystem::current_path(), ec));
  if (ec.value() == boost::system::errc::success)
  {
    ret = p.make_preferred().string();
  }
  return ret;
}

std::wstring executable_path_fallback(const wchar_t* argv0)
{
  if (argv0 == nullptr) return L"";
  if (argv0[0] == 0) return L"";
  if (wcsstr(argv0, wos_sep().c_str()) != nullptr)
  {
    boost::system::error_code ec;
    boost::filesystem::path p(
      boost::filesystem::canonical(argv0, boost::filesystem::current_path(), ec));
    if (ec.value() == boost::system::errc::success)
    {
      return p.make_preferred().wstring();
    }
  }
  std::wstring ret = search_path(argv0);
  if (!ret.empty())
  {
    return ret;
  }
  boost::system::error_code ec;
  boost::filesystem::path p(
    boost::filesystem::canonical(argv0, boost::filesystem::current_path(), ec));
  if (ec.value() == boost::system::errc::success)
  {
    ret = p.make_preferred().wstring();
  }
  return ret;
}

}} // namespace boost::detail
