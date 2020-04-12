cmake_minimum_required(VERSION 2.8.12)

project(ipftrace2)

# Taken from bpftrace (https://github.com/iovisor/bpftrace)
set(STATIC_LINKING OFF CACHE BOOL "Build ipftrace2 as a statically linked executable")
set(STATIC_LIBC OFF CACHE BOOL "Attempt to embed libc, only known to work with musl. Has issues with dlopen.")
set(BUILD_ASAN OFF CACHE BOOL "Build ipftrace with -fsanitize=address")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_compile_options("-Wall")
add_compile_options("-Wextra")

if(STATIC_LINKING)
  if(STATIC_LIBC)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
  endif(STATIC_LIBC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_LINK_SEARCH_START_STATIC TRUE)
  set(CMAKE_LINK_SEARCH_END_STATIC TRUE)
endif(STATIC_LINKING)

set(FIND_LIBRARY_USE_LIB64_PATHS TRUE)

find_package(LibDw REQUIRED)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(LibLZMA REQUIRED)
find_package(LibElf REQUIRED)
find_package(Threads REQUIRED)

include_directories(SYSTEM ${LIBDW_INCLUDE_DIRS})

set(CMAKE_REQUIRED_LIBRARIES)
set(CMAKE_REQUIRED_LINK_OPTIONS)

include(ExternalProject)

# Build newer version of libbpf
ExternalProject_Add(
  LibBpf
  GIT_REPOSITORY https://github.com/libbpf/libbpf
  GIT_TAG v0.0.7
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libbpf-0.0.7
  CONFIGURE_COMMAND ""
  SOURCE_SUBDIR src
  BUILD_COMMAND  make
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libbpf-0.0.7 make install && \\
                  PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libbpf-0.0.7 make install_headers
)

ExternalProject_Get_Property(LibBpf INSTALL_DIR)
set(LIBBPF_INCLUDE_DIRS ${INSTALL_DIR}/include)
include_directories(SYSTEM ${LIBBPF_INCLUDE_DIRS})
if(STATIC_LINKING)
  set(LIBBPF_LIBRARIES ${INSTALL_DIR}/lib64/libbpf.a)
else()
  set(LIBBPF_LIBRARIES ${INSTALL_DIR}/lib64/libbpf.so)
endif(STATIC_LINKING)

# Some libc like musl-libc doesn't have built-in fts. Test it.
CHECK_C_SOURCE_COMPILES("
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
int main(void) {
  FTS *fts_open(\"/\", 0, NULL);
  return 0;
}" LIBC_HAS_FTS)

if(NOT LIBC_HAS_FTS)
  find_package(LibFts REQUIRED)
endif()

add_subdirectory(src)
