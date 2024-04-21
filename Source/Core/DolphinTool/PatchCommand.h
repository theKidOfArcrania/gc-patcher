// Copyright 2021 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>
#include <vector>

namespace DolphinTool
{

#define PATCH_MAGIC 0x48504347 // GCPH
struct Xdelta3PatchHeader {
  uint32_t tag;
  uint32_t src_file_off;
  uint32_t out_file_off;
  /* uint8_t src_file[] */
  /* uint8_t out_file[] */
};

int PatchCommand(const std::vector<std::string>& args);
}  // namespace DolphinTool
