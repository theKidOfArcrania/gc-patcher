// Copyright 2021 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include "Common/StringUtil.h"
#include "Common/Version.h"

#include "DolphinTool/PatchCommand.h"

#ifdef _WIN32
#define main app_main
#endif

int main(int argc, char* argv[])
{
  // Take off the program name before passing arguments down
  const std::vector<std::string> args(argv + 1, argv + argc);

  return DolphinTool::PatchCommand(args);
}

#ifdef _WIN32
int wmain(int, wchar_t*[], wchar_t*[])
{
  std::vector<std::string> args = Common::CommandLineToUtf8Argv(GetCommandLineW());
  const int argc = static_cast<int>(args.size());
  std::vector<char*> argv(args.size());
  for (size_t i = 0; i < args.size(); ++i)
    argv[i] = args[i].data();

  return main(argc, argv.data());
}

#undef main
#endif
