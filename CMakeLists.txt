cmake_minimum_required(VERSION 3.16)
project(sashimi)
set(CMAKE_C_CLANG_TIDY
	clang-tidy;
	-header-filter=.;
	-checks=*;)
add_executable(test sashimi.c)
