add_executable(ipft
  btf.c
  bpf.c
  debuginfo.c
  dwarf.c
  ipftrace.c
  kallsyms.c
  perf.c
  script.c
  symsdb.c
  trace.c
  tracedb.c
  regex.c
)

if (BUILD_ASAN)
  if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    # target_link_options is supported in CMake 3.13 and newer
    message("Please use CMake 3.13 or newer to enable ASAN")
  endif()
  target_compile_definitions(ipft PRIVATE BUILD_ASAN)
  target_compile_options(ipft PUBLIC "-fsanitize=address")
  target_link_options(ipft PUBLIC "-fsanitize=address")
endif()

if(STATIC_LINKING)
  add_library(LIBLUA STATIC IMPORTED)
  add_library(LIBDW STATIC IMPORTED)
  add_library(ZLIB STATIC IMPORTED)
  add_library(BZIP2 STATIC IMPORTED)
  add_library(LIBLZMA STATIC IMPORTED)
  add_library(LIBELF STATIC IMPORTED)
  add_library(LIBPCRE STATIC IMPORTED)
  if(NOT LIBC_HAS_FTS)
    add_library(LIBFTS STATIC IMPORTED)
  endif()
else()
  add_library(LIBLUA STATIC IMPORTED)
  add_library(LIBDW SHARED IMPORTED)
  add_library(ZLIB SHARED IMPORTED)
  add_library(BZIP2 SHARED IMPORTED)
  add_library(LIBLZMA SHARED IMPORTED)
  add_library(LIBELF SHARED IMPORTED)
  add_library(LIBPCRE SHARED IMPORTED)
  if(NOT LIBC_HAS_FTS)
    add_library(LIBFTS SHARED IMPORTED)
  endif()
endif(STATIC_LINKING)

set_property(TARGET LIBLUA PROPERTY IMPORTED_LOCATION ${LIBLUA_LIBRARIES})
set_property(TARGET LIBDW PROPERTY IMPORTED_LOCATION ${LIBDW_LIBRARIES})
set_property(TARGET ZLIB PROPERTY IMPORTED_LOCATION ${ZLIB_LIBRARIES})
set_property(TARGET BZIP2 PROPERTY IMPORTED_LOCATION ${BZIP2_LIBRARIES})
set_property(TARGET LIBLZMA PROPERTY IMPORTED_LOCATION ${LIBLZMA_LIBRARIES})
set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
set_property(TARGET LIBPCRE PROPERTY IMPORTED_LOCATION ${LIBPCRE_LIBRARIES})
if(NOT LIBC_HAS_FTS)
  set_property(TARGET LIBFTS PROPERTY IMPORTED_LOCATION ${LIBFTS_LIBRARIES})
endif()

target_link_libraries(ipft
  LIBLUA
  LIBDW
  ZLIB
  BZIP2
  LIBLZMA
  LIBELF
  LIBPCRE
  -lpthread
  -ldl
  -lm
)

if(NOT LIBC_HAS_FTS)
  target_link_libraries(ipft LIBFTS)
endif()
