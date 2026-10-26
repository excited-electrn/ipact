cmake_minimum_required(VERSION 3.20)
project(ipact LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)

option(IPACT_SANITIZE "Build with ASan+UBSan" ON)

file(GLOB_RECURSE IPACT_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(ipact ${IPACT_SRC})
target_include_directories(ipact PUBLIC include src)
find_package(Threads REQUIRED)
target_link_libraries(ipact PUBLIC Threads::Threads)

if(IPACT_SANITIZE)
	target_compile_options(ipact PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
	target_link_options(ipact PUBLIC -fsanitize=address,undefined)
endif()

file(GLOB EXAMPLES CONFIGURE_DEPENDS examples/*.cpp)
foreach(example ${EXAMPLES})
    get_filename_component(name ${example} NAME_WE)
    add_executable(${name} ${example})
    target_link_libraries(${name} ipact)
endforeach()