cmake_minimum_required(VERSION 2.8)

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} SHARED_MODULE" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} " )

file(GLOB SOURCES *.c)

if (APPLE)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -I/usr/include -I/usr/local/include")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -I/usr/include -I/usr/local/include")
endif ()

find_package(CryptoC REQUIRED)
include_directories(${CryptoC_INCLUDE_DIRS})

find_package(CRYPTOC REQUIRED)
include_directories(${CRYPTOC_INCLUDE_DIRS})

message("value ${CryptoC_INCLUDE_DIRS}")
message("value ${CRYPTOC_INCLUDE_DIRS}")

add_library(mod_token_auth STATIC ${SOURCES})
