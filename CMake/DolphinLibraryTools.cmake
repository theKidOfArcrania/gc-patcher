# like add_library(new ALIAS old) but avoids add_library cannot create ALIAS target "new" because target "old" is imported but not globally visible. on older cmake
# This can be replaced with a direct alias call once our minimum is cmake 3.18
function(dolphin_alias_library new old)
  string(REPLACE "::" "" library_no_namespace ${old})
  if (NOT TARGET _alias_${library_no_namespace})
    add_library(_alias_${library_no_namespace} INTERFACE)
    target_link_libraries(_alias_${library_no_namespace} INTERFACE ${old})
  endif()
  add_library(${new} ALIAS _alias_${library_no_namespace})
endfunction()

# Makes an imported target if it doesn't exist.  Useful for when find scripts from older versions of cmake don't make the targets you need
function(dolphin_make_imported_target_if_missing target lib)
  if(${lib}_FOUND AND NOT TARGET ${target})
    add_library(_${lib} INTERFACE)
    target_link_libraries(_${lib} INTERFACE "${${lib}_LIBRARIES}")
    target_include_directories(_${lib} INTERFACE "${${lib}_INCLUDE_DIRS}")
    add_library(${target} ALIAS _${lib})
  endif()
endfunction()

function(dolphin_optional_system_library library)
  string(TOUPPER ${library} upperlib)
  message(STATUS "Hi ${upperlib}")
  set(USE_SYSTEM_${upperlib} "" CACHE STRING "Use system ${library} instead of bundled.  ON - Always use system and fail if unavailable, OFF - Always use bundled, AUTO - Use system if available, otherwise use bundled, blank - Delegate to USE_SYSTEM_LIBS.  Default is blank.")
  if("${USE_SYSTEM_${upperlib}}" STREQUAL "")
    if(APPROVED_VENDORED_DEPENDENCIES)
      string(TOLOWER ${library} lowerlib)
      if(lowerlib IN_LIST APPROVED_VENDORED_DEPENDENCIES)
        set(RESOLVED_USE_SYSTEM_${upperlib} AUTO PARENT_SCOPE)
      else()
        set(RESOLVED_USE_SYSTEM_${upperlib} ON PARENT_SCOPE)
      endif()
    else()
      set(RESOLVED_USE_SYSTEM_${upperlib} ${USE_SYSTEM_LIBS} PARENT_SCOPE)
    endif()
  else()
    set(RESOLVED_USE_SYSTEM_${upperlib} ${USE_SYSTEM_${upperlib}} PARENT_SCOPE)
  endif()
endfunction()

function(dolphin_add_bundled_library library bundled_path)
  string(TOUPPER ${library} upperlib)
  message(STATUS "Hi ${upperlib} ${RESOLVED_USE_SYSTEM_${upperlib}}")
  if (${RESOLVED_USE_SYSTEM_${upperlib}} STREQUAL "AUTO")
    message(STATUS "No system ${library} was found.  Using static ${library} from Externals.")
  else()
    message(STATUS "Using static ${library} from Externals")
  endif()
  if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${bundled_path}/CMakeLists.txt")
    message(FATAL_ERROR "No bundled ${library} was found.  Did you forget to checkout submodules?")
  endif()
  add_subdirectory(${bundled_path} EXCLUDE_FROM_ALL)
endfunction()

function(dolphin_find_optional_system_library library bundled_path)
  dolphin_optional_system_library(${library})
  string(TOUPPER ${library} upperlib)
  if(RESOLVED_USE_SYSTEM_${upperlib})
    find_package(${library} ${ARGN})
    # Yay for cmake packages being inconsistent
    if(DEFINED ${library}_FOUND)
      set(prefix ${library})
    else()
      set(prefix ${upperlib})
    endif()
    if((NOT ${found}) AND (NOT ${RESOLVED_USE_SYSTEM_${upperlib}} STREQUAL "AUTO"))
      message(FATAL_ERROR "No system ${library} was found.  Please install it or set USE_SYSTEM_${upperlib} to AUTO or OFF.")
    endif()
  endif()
  if(${prefix}_FOUND)
    message(STATUS "Using system ${library}")
    set(${prefix}_TYPE "System" PARENT_SCOPE)
  else()
    dolphin_add_bundled_library(${library} ${bundled_path})
    set(${prefix}_TYPE "Bundled" PARENT_SCOPE)
  endif()
endfunction()

function(dolphin_find_optional_system_library_pkgconfig library search alias bundled_path)
  dolphin_optional_system_library(${library})
  string(TOUPPER ${library} upperlib)
  if(RESOLVED_USE_SYSTEM_${upperlib})
    pkg_check_modules(${library} ${search} ${ARGN} IMPORTED_TARGET)
    if((NOT ${library}_FOUND) AND (NOT ${RESOLVED_USE_SYSTEM_${upperlib}} STREQUAL "AUTO"))
      message(FATAL_ERROR "No system ${library} was found.  Please install it or set USE_SYSTEM_${upperlib} to AUTO or OFF.")
    endif()
  endif()
  if(${library}_FOUND)
    message(STATUS "Using system ${library}")
    dolphin_alias_library(${alias} PkgConfig::${library})
    set(${library}_TYPE "System" PARENT_SCOPE)
  else()
    dolphin_add_bundled_library(${library} ${bundled_path})
    set(${library}_TYPE "Bundled" PARENT_SCOPE)
  endif()
endfunction()
