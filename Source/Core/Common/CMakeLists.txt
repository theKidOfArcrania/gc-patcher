add_library(common
  Assert.h
  BitField.h
  BitSet.h
  BitUtils.h
  BlockingLoop.h
  ChunkFile.h
  CodeBlock.h
  ColorUtil.cpp
  ColorUtil.h
  Common.h
  CommonFuncs.cpp
  CommonFuncs.h
  CommonPaths.h
  CommonTypes.h
  Config/Config.cpp
  Config/Config.h
  Config/ConfigInfo.cpp
  Config/ConfigInfo.h
  Config/Enums.h
  Config/Layer.cpp
  Config/Layer.h
  CPUDetect.h
  Crypto/AES.cpp
  Crypto/AES.h
  Crypto/bn.cpp
  Crypto/bn.h
  Crypto/ec.cpp
  Crypto/ec.h
  Crypto/HMAC.cpp
  Crypto/HMAC.h
  Crypto/SHA1.cpp
  Crypto/SHA1.h
  Debug/MemoryPatches.cpp
  Debug/MemoryPatches.h
  Debug/Threads.h
  Debug/Watches.cpp
  Debug/Watches.h
  DynamicLibrary.cpp
  DynamicLibrary.h
  EnumFormatter.h
  EnumMap.h
  EnumUtils.h
  Event.h
  FileSearch.cpp
  FileSearch.h
  FileUtil.cpp
  FileUtil.h
  FixedSizeQueue.h
  Flag.h
  FloatUtils.cpp
  FloatUtils.h
  FormatUtil.h
  FPURoundMode.h
  GekkoDisassembler.cpp
  GekkoDisassembler.h
  Hash.cpp
  Hash.h
  HookableEvent.h
  HttpRequest.cpp
  HttpRequest.h
  Image.cpp
  Image.h
  IniFile.cpp
  IniFile.h
  Inline.h
  IOFile.cpp
  IOFile.h
  JitRegister.cpp
  JitRegister.h
  Lazy.h
  LinearDiskCache.h
  Logging/ConsoleListener.h
  Logging/Log.h
  Logging/LogManager.cpp
  Logging/LogManager.h
  MathUtil.h
  Matrix.cpp
  Matrix.h
  MemArena.h
  MemoryUtil.cpp
  MemoryUtil.h
  MinizipUtil.h
  MsgHandler.cpp
  MsgHandler.h
  NandPaths.cpp
  NandPaths.h
  Network.cpp
  Network.h
  PcapFile.cpp
  PcapFile.h
  PerformanceCounter.cpp
  PerformanceCounter.h
  Profiler.cpp
  Profiler.h
  Random.cpp
  Random.h
  Result.h
  ScopeGuard.h
  SDCardUtil.cpp
  SDCardUtil.h
  Semaphore.h
  SettingsHandler.cpp
  SettingsHandler.h
  #SFMLHelper.cpp
  #SFMLHelper.h
  SmallVector.h
  SocketContext.cpp
  SocketContext.h
  SPSCQueue.h
  StringLiteral.h
  StringUtil.cpp
  StringUtil.h
  SymbolDB.cpp
  SymbolDB.h
  Thread.cpp
  Thread.h
  Timer.cpp
  Timer.h
  TraversalProto.h
  TypeUtils.h
  VariantUtil.h
  Version.cpp
  Version.h
  WindowSystemInfo.h
  WorkQueueThread.h
)

add_dependencies(common dolphin_scmrev)

if(NOT MSVC AND _M_ARM_64)
  set_source_files_properties(
    Crypto/AES.cpp
    Crypto/SHA1.cpp
    PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
endif()

target_link_libraries(common
PUBLIC
  ${CMAKE_THREAD_LIBS_INIT}
  fmt::fmt
  MbedTLS::mbedtls
  minizip::minizip

PRIVATE
  Iconv::Iconv
  spng::spng
  ${VTUNE_LIBRARIES}
)

if (APPLE)
  target_link_libraries(common
  PRIVATE
    ${APPKIT_LIBRARY}
    ${COREFOUNDATION_LIBRARY}
    ${IOK_LIBRARY}
  )
elseif(WIN32)
  target_link_libraries(common
  PRIVATE
    kernel32.lib
    shlwapi.lib
    winmm.lib
  )
  if (_M_X86_64)
    target_link_libraries(common PRIVATE opengl32.lib)
  endif()
elseif (ANDROID)
  target_link_libraries(common
  PRIVATE
    androidcommon
  )
endif()

if(ANDROID)
  target_sources(common PRIVATE
    Logging/ConsoleListenerDroid.cpp
    MemArenaAndroid.cpp
  )
elseif(WIN32)
  target_sources(common PRIVATE
    LdrWatcher.cpp
    LdrWatcher.h
    Logging/ConsoleListenerWin.cpp
    MemArenaWin.cpp
  )
else()
  target_sources(common PRIVATE
    Logging/ConsoleListenerNix.cpp
    MemArenaUnix.cpp
  )
endif()

if(_M_ARM_64)
  target_sources(common PRIVATE
    Arm64Emitter.cpp
    Arm64Emitter.h
    ArmCommon.h
    ArmCPUDetect.cpp
    ArmFPURoundMode.cpp
  )
else()
  if(_M_X86) #X86
    target_sources(common PRIVATE
      x64ABI.cpp
      x64ABI.h
      x64Emitter.cpp
      x64Emitter.h
      x64FPURoundMode.cpp
      x64CPUDetect.cpp
      x64Reg.h
    )
  else() # Generic
    target_sources(common PRIVATE
      GenericFPURoundMode.cpp
      GenericCPUDetect.cpp
    )
  endif()
endif()


if(WIN32)
  target_sources(common PRIVATE
    CompatPatches.cpp
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(common PUBLIC dl rt)
endif()

if(WIN32)
  target_sources(common PRIVATE HRWrap.h HRWrap.cpp)
endif()

if(MSVC)
  # Add precompiled header
  target_link_libraries(common PRIVATE use_pch)
endif()
