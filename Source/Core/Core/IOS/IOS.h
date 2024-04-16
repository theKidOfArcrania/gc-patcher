// Copyright 2017 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Common/CommonTypes.h"
#include "Core/HW/SystemTimers.h"
#include "Core/IOS/IOSC.h"

class PointerWrap;

namespace Core
{
class System;
}

namespace IOS::HLE
{
namespace FS
{
class FileSystem;
}

class Device;
class ESCore;
class ESDevice;
class FSCore;
class FSDevice;
class WiiSockMan;

struct Request;
struct OpenRequest;

struct IPCReply
{
  /// Constructs a reply with an average reply time.
  /// Please avoid using this function if more accurate timings are known.
  explicit IPCReply(s32 return_value_);
  explicit IPCReply(s32 return_value_, u64 reply_delay_ticks_);

  s32 return_value;
  u64 reply_delay_ticks;
};

constexpr SystemTimers::TimeBaseTick IPC_OVERHEAD_TICKS = 2700_tbticks;

// Used to make it more convenient for functions to return timing information
// without having to explicitly keep track of ticks in callers.
class Ticks
{
public:
  Ticks(u64* ticks = nullptr) : m_ticks(ticks) {}

  void Add(u64 ticks)
  {
    if (m_ticks != nullptr)
      *m_ticks += ticks;
  }

private:
  u64* m_ticks = nullptr;
};

template <typename ResultProducer>
IPCReply MakeIPCReply(u64 ticks, const ResultProducer& fn)
{
  const s32 result_value = fn(Ticks{&ticks});
  return IPCReply{result_value, ticks};
}

template <typename ResultProducer>
IPCReply MakeIPCReply(const ResultProducer& fn)
{
  return MakeIPCReply(0, fn);
}

enum IPCCommandType : u32
{
  IPC_CMD_OPEN = 1,
  IPC_CMD_CLOSE = 2,
  IPC_CMD_READ = 3,
  IPC_CMD_WRITE = 4,
  IPC_CMD_SEEK = 5,
  IPC_CMD_IOCTL = 6,
  IPC_CMD_IOCTLV = 7,
  // This is used for replies to commands.
  IPC_REPLY = 8,
};

enum class MemorySetupType
{
  IOSReload,
  Full,
};

enum class HangPPC : bool
{
  No = false,
  Yes = true,
};

void RAMOverrideForIOSMemoryValues(MemorySetupType setup_type);

void WriteReturnValue(s32 value, u32 address);

}  // namespace IOS::HLE
