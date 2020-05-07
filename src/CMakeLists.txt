add_executable(ipftrace2
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
)

if(STATIC_LINKING)
  add_library(LIBLUA STATIC IMPORTED)
  add_library(LIBDW STATIC IMPORTED)
  add_library(ZLIB STATIC IMPORTED)
  add_library(BZIP2 STATIC IMPORTED)
  add_library(LIBLZMA STATIC IMPORTED)
  add_library(LIBELF STATIC IMPORTED)
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
if(NOT LIBC_HAS_FTS)
  set_property(TARGET LIBFTS PROPERTY IMPORTED_LOCATION ${LIBFTS_LIBRARIES})
endif()

target_link_libraries(ipftrace2
  LIBLUA
  LIBDW
  ZLIB
  BZIP2
  LIBLZMA
  LIBELF
  -lpthread
  -ldl
  -lm
)

if(NOT LIBC_HAS_FTS)
  target_link_libraries(ipftrace2 LIBFTS)
endif()
