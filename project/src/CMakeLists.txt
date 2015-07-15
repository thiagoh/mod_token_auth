cmake_minimum_required(VERSION 2.8)

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} SHARED_MODULE" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} " )

file(GLOB SOURCES *.c)

add_library(mod_token_auth STATIC ${SOURCES})

#find_package(CryptoC REQUIRED)
#include_directories(${CryptoC_INCLUDE_DIRS})