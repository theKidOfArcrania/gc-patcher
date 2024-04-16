add_library(core
  CommonTitles.h
  HW/SystemTimers.h
  IOS/Device.h
  IOS/ES/ES.h
  IOS/ES/Formats.cpp
  IOS/ES/Formats.h
  IOS/IOS.h
  IOS/IOSC.cpp
  IOS/IOSC.h
  IOS/Uids.h
)

target_link_libraries(core
PUBLIC
  common
  discio
  MbedTLS::mbedtls
  pugixml
  RangeSet::RangeSet

PRIVATE
  fmt::fmt
  LZO::LZO
  LZ4::LZ4
  ZLIB::ZLIB
)
