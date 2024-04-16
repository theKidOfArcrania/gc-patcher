########################################
# General setup
#
cmake_minimum_required(VERSION 3.13)

cmake_policy(SET CMP0079 NEW) # let target_link_libraries() link to a target defined in a different directory
cmake_policy(SET CMP0080 OLD) # allow using BundleUtilities at configure time

if (POLICY CMP0099)
  cmake_policy(SET CMP0099 NEW) # Propagate INTERFACE_LINK_OPTIONS from private dependencies, used by MacOS framework builds of SDL
endif()

# Weird chicken-and-egg problem: We can't check the compiler before the project() call, but we have to set the policies before it.
# So we do this in two steps: Set the policies if they exist, then error out afterwards if we end up being MSVC and they don't exist.
if (POLICY CMP0117)
  cmake_policy(SET CMP0091 NEW) # MSVC runtime library flags are selected by an abstraction.
  cmake_policy(SET CMP0092 NEW) # MSVC warning flags are not in CMAKE_{C,CXX}_FLAGS by default.
  cmake_policy(SET CMP0117 NEW) # MSVC RTTI flag will not be added by default.
endif()

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW) # MSVC debug information format flags are selected by an abstraction.
endif()

# Minimum OS X version.
# This is inserted into the Info.plist as well.
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15.0" CACHE STRING "")

set(CMAKE_USER_MAKE_RULES_OVERRIDE "CMake/FlagsOverride.cmake")

project(mod-patcher)

if (MSVC)
  if (POLICY CMP0117)
    # cmake is a weird language. You can't do if(not POLICY)
  else()
    message(FATAL_ERROR "Please update to CMake 3.20 or higher.")
  endif()

  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 23)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

set(COMPILER ${CMAKE_CXX_COMPILER_ID})
if (COMPILER STREQUAL "GNU")
  set(COMPILER "GCC") # perfer printing GCC instead of GNU
endif()

# Enforce minimium compiler versions that support the c++20 features we use
set (GCC_min_version 10)
set (Clang_min_version 12)
set (AppleClang_min_version 13.0.0)
set (min_xcode_version "13.0") # corrosponding xcode version for AppleClang_min_version
set (MSVC_min_version 14.32)
set (min_vs_version "2022 17.2.3") # corrosponding Visual Studio version for MSVC_min_version

message(STATUS "Using ${COMPILER} ${CMAKE_CXX_COMPILER_VERSION}")

if ("-" STREQUAL "${${COMPILER}_min_version}-")
  message(WARNING "Unknown compiler ${COMPILER}, assuming it is new enough")
else()
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS  ${${COMPILER}_min_version})
    message(FATAL_ERROR "Requires GCC ${GCC_min_version}, Clang ${Clang_min_version},"
    " AppleClang ${AppleClang_min_version} (Xcode ${min_xcode_version}),"
    " or MSVC ${MSVC_min_version} (Visual Studio ${min_vs_version}) or higher")
  endif()
endif()

# Name of the Dolphin distributor. If you redistribute Dolphin builds (forks,
# unofficial builds) please consider identifying your distribution with a
# unique name here.
set(DISTRIBUTOR "None" CACHE STRING "Name of the distributor.")


list(APPEND CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/CMake
)

# Support functions
include(CheckAndAddFlag)
include(CheckCCompilerFlag)
include(DolphinCompileDefinitions)
include(DolphinDisableWarningsMSVC)
include(DolphinLibraryTools)
include(GNUInstallDirs)
include(RemoveCompileFlag)

set(USE_SYSTEM_LIBS "AUTO" CACHE STRING "Use system libraries instead of bundled libraries.  ON - Always use system and fail if unavailable, OFF - Always use bundled, AUTO - Use system if available, otherwise use bundled.  Default is AUTO")
option(ENABLE_QT "Enable Qt (Default)" ON)
option(ENABLE_HEADLESS "Enables running Dolphin as a headless variant" OFF)
if(UNIX)
  # Builds a relocatable binary on Linux.
  # The Sys folder will need to be copied to the Binaries folder.
  option(LINUX_LOCAL_DEV "Enable relocatable binary" OFF)
endif()

option(ENABLE_LTO "Enables Link Time Optimization" OFF)

# Enable folders for IDE
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Set where the binary files will be built.  The program will not execute from
# here.  You must run "make install" to install these to the proper location
# as defined above.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Binaries)

if (WIN32)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Binary)

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    string(APPEND CMAKE_RUNTIME_OUTPUT_DIRECTORY /x64)
  elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    string(APPEND CMAKE_RUNTIME_OUTPUT_DIRECTORY /ARM64)
  endif()
endif()

# setup CCache
include(CCache)

if(CMAKE_GENERATOR MATCHES "Ninja")
  check_and_add_flag(DIAGNOSTICS_COLOR -fdiagnostics-color)
elseif(CMAKE_GENERATOR MATCHES "Visual Studio")
  # Only MSBuild needs this, other generators will compile one file at a time
  add_compile_options("/MP")
endif()

if(MSVC)
  check_and_add_flag(EXCEPTIONS /EHsc)
  dolphin_compile_definitions(_DEBUG DEBUG_ONLY)

  # Disable RTTI
  add_compile_options(/GR-)

  # Set warning level 4 (the highest)
  add_compile_options(/W4)

  # Treat all warnings as errors
  add_compile_options(/WX)

  # Disable some warnings
  add_compile_options(
    /wd4201 # nonstandard extension used : nameless struct/union
    /wd4127 # conditional expression is constant
    /wd4100 # 'identifier' : unreferenced formal parameter
    /wd4200 # InputCommon fix temp.
    /wd4244 # 'conversion' conversion from 'type1' to 'type2', possible loss of data
    /wd4121 # 'symbol' : alignment of a member was sensitive to packing
    /wd4324 # Padding was added at the end of a structure because you specified a __declspec(align) value.
    /wd4714 # function 'function' marked as __forceinline not inlined
    /wd4351 # new behavior: elements of array 'array' will be default initialized
    # TODO: Enable this warning once possible
    /wd4245 # conversion from 'type1' to 'type2', signed/unsigned mismatch
    # Currently jits use some annoying code patterns which makes this common
  )

  # Additional warnings
  add_compile_options(
    /w44263 # Non-virtual member function hides base class virtual function
    /w44265 # Class has virtual functions, but destructor is not virtual
    /w44946 # Reinterpret cast between related types
  )

  # All files are encoded as UTF-8
  add_compile_options(/utf-8)

  # Ignore warnings in external headers
  add_compile_options(/external:anglebrackets)
  add_compile_options(/external:W0)
  add_compile_options(/external:templates-)

  # Request deterministic builds
  add_compile_options(/experimental:deterministic)
  add_link_options(/experimental:deterministic)

  # Enable function-level linking
  add_compile_options(/Gy)
  # Generate intrinsic functions
  add_compile_options(/Oi)
  # Enable buffer security check on Debug, disable otherwise
  add_compile_options($<IF:$<CONFIG:Debug>,/GS,/GS->)
  # Remove unreferenced inline functions/data to reduce link time and catch bugs
  # Note: In msbuild build, this gets set by msbuild by default
  add_compile_options(/Zc:inline)
  # Fix various other non-conformant behaviors
  add_compile_options(/Zc:__cplusplus,enumTypes,externConstexpr,preprocessor,templateScope,throwingNew)
  # Enforce strict volatile semantics as per ISO C++
  add_compile_options(/volatile:iso)

  # Use 'precise' floating point model
  add_compile_options(/fp:precise)

  string(APPEND CMAKE_EXE_LINKER_FLAGS " /NXCOMPAT")
  # Generate debug data
  string(APPEND CMAKE_EXE_LINKER_FLAGS " /DEBUG")
  # Eliminate dead code and data
  string(APPEND CMAKE_EXE_LINKER_FLAGS " /OPT:REF /OPT:ICF")
else()
  add_definitions(-D_DEFAULT_SOURCE)

  # gcc uses some optimizations which might break stuff without this flag
  check_and_add_flag(NO_STRICT_ALIASING -fno-strict-aliasing)
  check_and_add_flag(NO_EXCEPTIONS -fno-exceptions)

  check_and_add_flag(VISIBILITY_INLINES_HIDDEN -fvisibility-inlines-hidden)
  check_and_add_flag(VISIBILITY_HIDDEN -fvisibility=hidden)

  check_and_add_flag(FOMIT_FRAME_POINTER -fomit-frame-pointer NO_DEBINFO_ONLY)

  dolphin_compile_definitions(_DEBUG DEBUG_ONLY)
  check_and_add_flag(GGDB -ggdb DEBUG_ONLY)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # GNU ar: Create thin archive files.
    # Requires binutils-2.19 or later.
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> qcTP <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_APPEND   "<CMAKE_AR> qTP  <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcTP <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_APPEND "<CMAKE_AR> qTP  <TARGET> <LINK_FLAGS> <OBJECTS>")
  endif()
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  if(NOT MACOS_USE_DEFAULT_SEARCH_PATH)
    # Hack up the path to prioritize the path to built-in OS libraries to
    # increase the chance of not depending on a bunch of copies of them
    # installed by MacPorts, Fink, Homebrew, etc, and ending up copying
    # them into the bundle.  Since we optionally depend on libraries which
    # are not part of OS X (ffmpeg, etc.), however, don't remove the default
    # path entirely as was done in a previous version of this file.  This is
    # still kinda evil, since it defeats the user's path settings...
    # See http://www.cmake.org/cmake/help/v3.0/command/find_program.html
    list(APPEND CMAKE_PREFIX_PATH "/usr")
  endif()

  # Prevents Xcode from overriding the -fno-strict-aliasing flag
  set(CMAKE_XCODE_ATTRIBUTE_GCC_STRICT_ALIASING NO)

  # Specify target CPUs.
  if(_ARCH_64 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    check_and_add_flag(HAVE_MSSSE3 -mssse3)
    check_and_add_flag(HAVE_ARCH_CORE2 -march=core2)
  endif()
  # Linker flags.
  # Drop unreachable code and data.
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip,-dead_strip_dylibs")

  # Set FMT_EXCEPTIONS = 0, for consistency with -fno-exceptions earlier.
  # If we set only -fno-exceptions, fmt fails to compile when included from
  # Objective-C++ because fmt tries try to use throw because __EXCEPTIONS is defined.
  add_definitions(-DFMT_EXCEPTIONS=0)

  # find_library(APPKIT_LIBRARY AppKit)
  # find_library(APPSERV_LIBRARY ApplicationServices)
  # find_library(CARBON_LIBRARY Carbon)
  # find_library(COCOA_LIBRARY Cocoa)
  # find_library(COREFOUNDATION_LIBRARY CoreFoundation)
  # find_library(CORESERV_LIBRARY CoreServices)
  # find_library(FORCEFEEDBACK_LIBRARY ForceFeedback)
  # find_library(FOUNDATION_LIBRARY Foundation)
  # find_library(IOB_LIBRARY IOBluetooth)
  # find_library(IOK_LIBRARY IOKit)
  # find_library(OPENGL_LIBRARY OpenGL)
endif()

if(ENABLE_LTO)
  if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    add_compile_options(/GL)
    string(APPEND CMAKE_EXE_LINKER_FLAGS " /LTCG")
  else()
    check_and_add_flag(LTO -flto)
    if(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
      set(CMAKE_AR gcc-ar)
      set(CMAKE_RANLIB gcc-ranlib)
    endif()
  endif()
endif()

if(UNIX)
  if(LINUX_LOCAL_DEV)
    add_definitions(-DLINUX_LOCAL_DEV)
  endif()
endif()

# BSDs put packages in /usr/local instead of /usr, so we need to
# force CMake to look in those directories by default, too.
# All commands and submodule commands also need to see these
# changes, so just setting them in the project scope via
# include_directories and link_directories is not sufficient
if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|NetBSD")
  set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/usr/local")
  set(CMAKE_REQUIRED_INCLUDES "/usr/local/include")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/usr/local/lib")

  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14.0)
    # Workaround: the llvm libc++ and versions of clang eariler than 14 have a bug with consteval
    # so we define FMT_CONSTEVAL to blank to just disable consteval in fmt
    add_definitions(-DFMT_CONSTEVAL=)
  endif()
endif()

# Dolphin requires threads.
find_package(Threads)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Build type (Release/Debug/RelWithDebInfo/MinSizeRel)" FORCE)
endif()

if(ENABLE_HEADLESS)
  message(STATUS "Enabling Headless! Disabling GUI.")
  set(ENABLE_QT 0)
endif()

# Set file offset size to 64 bits. On modern Unixes, this is typically already the case. Exceptions:
#
# glibc may default to 32 bits. This can be configured by setting _FILE_OFFSET_BITS=64.
#
# bionic (Android) defaults to 32 bits for 32-bit ABIs. Here too we can use _FILE_OFFSET_BITS=64,
# but only on API 25 and up. Since we're currently supporting older API levels and 32-bit Android
# isn't a build configuration we officially support, let's leave this as it is for now.
# More details: https://android.googlesource.com/platform/bionic/+/master/docs/32-bit-abi.md
if(NOT ANDROID AND NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  add_definitions(-D_FILE_OFFSET_BITS=64)
  add_definitions(-D_LARGEFILE_SOURCE)
endif()

########################################
# Dependency checking
#
# TODO: We should have options for dependencies included in the externals to
# override autodetection of system libraries and force the usage of the
# externals.
include(CheckLib)
include(CheckCXXSourceRuns)

if(UNIX)
  message(STATUS "Using named pipes as controller inputs")
  add_definitions(-DUSE_PIPES=1)
  message(STATUS "Watching game memory for changes")
  add_definitions(-DUSE_MEMORYWATCHER=1)
endif()

########################################
# Process externals and setup their include directories
#
# NOTES about adding Externals:
#   - If an external provides a target, or one can be introduced with find_package, consider using it.
#     - If a target doesn't exist, consider introducing a target for it with add_library and adding all necessary
#       includes, definitions, etc, to that target. This way, only libraries that need those attributes simply
#       need to link that target in, as opposed to them being provided to every library
#       (which is the case with the directory-based include_directories, add_definitions, etc)
#
#   - make sure to tell cmake to link them statically or dynamically (most
#     should be linked statically)
#   - place the CMakeLists.txt in the first-level subdirectory, e.g.
#     Externals/zlib/CMakeLists.txt (that is: NOT in some Src/ subdirectory)
#
add_subdirectory(Externals/cpp-optparse)

dolphin_find_optional_system_library(BZip2 Externals/bzip2)

dolphin_find_optional_system_library(LibLZMA Externals/liblzma)
# Imported target added in CMake 3.14
dolphin_make_imported_target_if_missing(LibLZMA::LibLZMA LIBLZMA)

dolphin_find_optional_system_library_pkgconfig(ZSTD libzstd>=1.4.0 zstd::zstd Externals/zstd)

dolphin_find_optional_system_library_pkgconfig(ZLIB zlib-ng ZLIB::ZLIB Externals/zlib-ng)

dolphin_find_optional_system_library_pkgconfig(MINIZIP minizip>=3.0.0 minizip::minizip Externals/minizip)

dolphin_find_optional_system_library(LZO Externals/LZO)

dolphin_find_optional_system_library_pkgconfig(lz4 liblz4>=1.8 LZ4::LZ4 Externals/lz4)

dolphin_find_optional_system_library_pkgconfig(SPNG spng spng::spng Externals/libspng)

dolphin_find_optional_system_library(fmt Externals/fmt 10.1)

dolphin_find_optional_system_library(MBEDTLS Externals/mbedtls 2.28)

dolphin_find_optional_system_library(pugixml Externals/pugixml)

if(NOT ANDROID)
  dolphin_find_optional_system_library(Iconv Externals/libiconv-1.14)
else()
  message(STATUS "Using static iconv from Externals")
  add_subdirectory(Externals/libiconv-1.14 EXCLUDE_FROM_ALL)
endif()

add_subdirectory(Externals/rangeset)

########################################
# Pre-build events: Define configuration variables and write SCM info header
#

# Remove in-tree revision information generated by Visual Studio
# This is because the compiler will check in-tree first and use this, even if it is outdated
file(REMOVE "${PROJECT_SOURCE_DIR}/Source/Core/Common/scmrev.h")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/Source/Core/Common)
if (NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/Source/Core/Common/scmrev.h)
	file(TOUCH ${CMAKE_CURRENT_BINARY_DIR}/Source/Core/Common/scmrev.h)
endif()

find_package(Git)
if(NOT GIT_FOUND)
	set(GIT_EXECUTABLE "")
endif()

add_custom_target(
	dolphin_scmrev
	${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DPROJECT_BINARY_DIR=${PROJECT_BINARY_DIR} -DDISTRIBUTOR=${DISTRIBUTOR} -DDOLPHIN_DEFAULT_UPDATE_TRACK=${DOLPHIN_DEFAULT_UPDATE_TRACK} -DGIT_FOUND=${GIT_FOUND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DDOLPHIN_WC_REVISION=${DOLPHIN_WC_REVISION} -DDOLPHIN_WC_DESCRIBE=${DOLPHIN_WC_DESCRIBE} -DDOLPHIN_WC_BRANCH=${DOLPHIN_WC_BRANCH} -P ${CMAKE_SOURCE_DIR}/CMake/ScmRevGen.cmake
	BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/Source/Core/Common/scmrev.h
	VERBATIM
)

# This is here so #include "Common/scmrev.h" finds the generated header.
include_directories("${PROJECT_BINARY_DIR}/Source/Core")

########################################
# Process Dolphin source now that all setup is complete
#
add_subdirectory(Source)

# TODO: what needs to be installed
