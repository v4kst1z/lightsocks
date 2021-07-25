cmake_minimum_required (VERSION 3.8)

project ("Proxy")

set (CMAKE_CXX_STANDARD 11)

IF(CMAKE_BUILD_TYPE MATCHES Debug)
  message("Debug build.")
  set (CMAKE_BUILD_TYPE Debug)
  set (CMAKE_CXX_FLAGS_DEBUG "-W -g")
  set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS_DEBUG} -g -fno-omit-frame-pointer -fsanitize=address")
ELSEIF(CMAKE_BUILD_TYPE MATCHES Release)
  message("Release build.")
  set (CMAKE_CXX_FLAGS_RELEASE)
ELSE()
  message("Some other build type.")
ENDIF()

set (CPPNET ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/CppNet)

if(NOT EXISTS "${CPPNET}")
  add_custom_target(third)
  include("./cmake/cppnet.cmake")
  add_dependencies(third CppNet)
endif()

include_directories ("lightsocks")

add_subdirectory(src)

