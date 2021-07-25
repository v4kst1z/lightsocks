cmake_minimum_required (VERSION 3.8)

project ("lightsocks")

find_package(OpenSSL REQUIRED) 
if (OPENSSL_FOUND)
  include_directories(/usr/include/openssl)
  message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
  message(STATUS "library ${OPENSSL_LIBRARIES}")
  message(STATUS "header files ${OPENSSL_INCLUDE_DIRS}")
endif()

set (CPPNET ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/CppNet)

include_directories(
    ${CPPNET}/install/include
    ../include/ 
)

link_directories(
    ${CPPNET}/install/lib
)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../bin/) 

file(GLOB LOCAL_LIST "local/*.cpp" "encrypt/*.cpp")
file(GLOB SERVER_LIST "server/*.cpp" "encrypt/*.cpp")

add_executable(sslocal ${LOCAL_LIST})
add_executable(ssserver ${SERVER_LIST})

add_dependencies(sslocal third)
add_dependencies(ssserver third)

target_link_libraries(ssserver ${OPENSSL_LIBRARIES})
target_link_libraries(sslocal ${OPENSSL_LIBRARIES})

target_link_libraries(sslocal libcppnet_shared.so)
target_link_libraries(ssserver libcppnet_shared.so)
