cmake_minimum_required(VERSION 3.20)
project(ipact DESCRIPTION "A C++20 TCP and IPv4 stack for Linux" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)

# Phase 15: build with sanitizers, e.g.  cmake -B build-asan -DIPACT_SANITIZE=address,undefined
#                                        cmake -B build-tsan -DIPACT_SANITIZE=thread   (cannot be combined with address)
set(IPACT_SANITIZE "" CACHE STRING "comma-separated sanitizers for -fsanitize=")
if(IPACT_SANITIZE)
    add_compile_options(-fsanitize=${IPACT_SANITIZE} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${IPACT_SANITIZE})
endif()

file(GLOB_RECURSE IPACT_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(ipact ${IPACT_SRC})
target_include_directories(ipact PUBLIC include src)     # PUBLIC: the examples include "io/...", "tcp/..."
find_package(Threads REQUIRED)
target_link_libraries(ipact PUBLIC Threads::Threads)

# Every .cpp in examples/ becomes its own program, named after the file.
file(GLOB EXAMPLES CONFIGURE_DEPENDS examples/*.cpp)
foreach(example ${EXAMPLES})
    get_filename_component(name ${example} NAME_WE)
    add_executable(${name} ${example})
    target_link_libraries(${name} ipact)
endforeach()

# Phase 15: tests. Run them all with:  ctest --test-dir build --output-on-failure
enable_testing()
foreach(t unit_tests sim_test)
    add_executable(${t} tests/${t}.cpp)
    target_link_libraries(${t} ipact)
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# Fuzzing: this builds the random-input driver (works with g++). For coverage-guided fuzzing with
# clang, see the command in the header of tests/fuzz_parse.cpp.
add_executable(fuzz_parse tests/fuzz_parse.cpp)
target_compile_definitions(fuzz_parse PRIVATE FUZZ_STANDALONE)
target_link_libraries(fuzz_parse ipact)
add_test(NAME fuzz_parse COMMAND fuzz_parse 200000)
