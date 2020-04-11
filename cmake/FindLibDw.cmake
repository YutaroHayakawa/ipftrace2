find_path (LIBDW_INCLUDE_DIRS
  NAMES
    dwarf.h
    libdwfl.h
  PATHS
    /usr/include
    /usr/include/elfutils
    /usr/local/include
    /usr/local/include/elfutils
    /opt/local/include
    /opt/local/include/elfutils
    /sw/include
    /sw/include/elfutils
    ENV CPATH)

find_library (LIBDW_LIBRARIES
  NAMES
    dw
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBDW_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibDw "Please install the elfutils development package"
  LIBDW_LIBRARIES
  LIBDW_INCLUDE_DIRS)

mark_as_advanced(LIBDW_INCLUDE_DIRS LIBDW_LIBRARIES)
