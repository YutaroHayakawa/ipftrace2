add_executable(ipft
  btf.c
  ipftrace.c
  kallsyms.c
  output.c
  output_aggregate.c
  output_stream.c
  regex.c
  symsdb.c
  trace.c
  traceable_set.c
  tracedb.c
  utils.c
  script.c
)

if(STATIC_LINKING)
  add_library(ZLIB STATIC IMPORTED)
  add_library(LIBELF STATIC IMPORTED)
  add_library(LIBPCRE STATIC IMPORTED)
  add_library(LIBBPF STATIC IMPORTED)
  add_library(LIBLUA STATIC IMPORTED)
  if(NOT LIBC_HAS_FTS)
    add_library(LIBFTS STATIC IMPORTED)
  endif()
else()
  add_library(ZLIB SHARED IMPORTED)
  add_library(LIBELF SHARED IMPORTED)
  add_library(LIBPCRE SHARED IMPORTED)
  add_library(LIBBPF SHARED IMPORTED)
  add_library(LIBLUA STATIC IMPORTED)
  if(NOT LIBC_HAS_FTS)
    add_library(LIBFTS SHARED IMPORTED)
  endif()
endif(STATIC_LINKING)

set_property(TARGET ZLIB PROPERTY IMPORTED_LOCATION ${ZLIB_LIBRARIES})
set_property(TARGET LIBELF PROPERTY IMPORTED_LOCATION ${LIBELF_LIBRARIES})
set_property(TARGET LIBPCRE PROPERTY IMPORTED_LOCATION ${LIBPCRE_LIBRARIES})
set_property(TARGET LIBBPF PROPERTY IMPORTED_LOCATION ${LIBBPF_LIBRARIES})
set_property(TARGET LIBLUA PROPERTY IMPORTED_LOCATION ${LIBLUA_LIBRARIES})
if(NOT LIBC_HAS_FTS)
  set_property(TARGET LIBFTS PROPERTY IMPORTED_LOCATION ${LIBFTS_LIBRARIES})
endif()

target_link_libraries(ipft
  LIBBPF
  ZLIB
  LIBELF
  LIBPCRE
  LIBLUA
  -lpthread
  -ldl
  -lm
)

if(NOT LIBC_HAS_FTS)
  target_link_libraries(ipft LIBFTS)
endif()
