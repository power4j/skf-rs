cmake_minimum_required(VERSION 4.0)
project(skf-abi-stub C)

set(CMAKE_C_STANDARD 11)
add_compile_definitions(SKF_HAS_ECCDECRYPT)
include_directories(include)

add_executable(c_src
        include/sgd.h
        include/skf.h
        src/skf_stub.c)
