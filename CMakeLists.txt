cmake_minimum_required(VERSION 3.16)
project(sashimi LANGUAGES C)
set(CMAKE_C_CLANG_TIDY
	clang-tidy;
	-checks=*;)

add_library(rawfish SHARED src/sashimi.c)

include(CTest)
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
	add_subdirectory(tests)
endif()

enable_testing()

