find_path (LIBPCRE_INCLUDE_DIRS
  NAMES
    pcre2.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

  find_library (LIBPCRE_LIBRARIES
  NAMES
    pcre2-8
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBDW_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibPcre "Please install the libpcre2 development package"
  LIBPCRE_LIBRARIES
  LIBPCRE_INCLUDE_DIRS)

mark_as_advanced(LIBPCRE_INCLUDE_DIRS LIBPCRE_LIBRARIES)
