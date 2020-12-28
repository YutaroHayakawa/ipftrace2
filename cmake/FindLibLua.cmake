find_path (LIBLUA_INCLUDE_DIRS
  NAMES
    lua.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBLUA_LIBRARIES
  NAMES
    lua
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
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibLua "Please install the liblua package"
  LIBLUA_LIBRARIES
  LIBLUA_INCLUDE_DIRS)

mark_as_advanced(LIBLUA_INCLUDE_DIRS LIBLUA_LIBRARIES)
