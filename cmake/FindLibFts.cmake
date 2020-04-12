find_path (LIBFTS_INCLUDE_DIRS
  NAMES
    fts.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBFTS_LIBRARIES
  NAMES
    fts
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBFTS_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibFts "Please install the package wihch provides fts(3)"
  LIBFTS_LIBRARIES
  LIBFTS_INCLUDE_DIRS)

mark_as_advanced(LIBFTS_INCLUDE_DIRS LIBFTS_LIBRARIES)
