find_path (LIBBPF_INCLUDE_DIRS
  NAMES
    libbpf.h
  PATHS
    /usr/include
    /usr/include/bpf
    /usr/local/include
    /usr/local/include/bpf
    /opt/local/include
    /opt/local/include/bpf
    /sw/include
    /sw/include/bpf
    ENV CPATH)

find_library (LIBBPF_LIBRARIES
  NAMES
    bpf
  PATHS
    /usr/lib
    /usr/lib64
    /usr/local/lib
    /usr/local/lib64
    /opt/local/lib
    /opt/local/lib64
    /sw/lib
    /sw/lib64
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf "Please install the libbpf package"
  LIBBPF_LIBRARIES
  LIBBPF_INCLUDE_DIRS)

mark_as_advanced(LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES)
