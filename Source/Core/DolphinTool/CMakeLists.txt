add_executable(mpatch
  PatchCommand.cpp
  PatchCommand.h
  ToolMain.cpp
)

set_target_properties(mpatch PROPERTIES OUTPUT_NAME mpatch)

target_link_libraries(mpatch
PRIVATE
  xdelta
  discio
  cpp-optparse
  fmt::fmt
)

if(MSVC)
  # Add precompiled header
  target_link_libraries(mpatch PRIVATE use_pch)
endif()

set(CPACK_PACKAGE_EXECUTABLES ${CPACK_PACKAGE_EXECUTABLES} mpatch)
install(TARGETS mpatch RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
