find_path (LIBREADLINE_INCLUDE_DIRS
  NAMES
    readline.h
  PATHS
    /usr/include
    /usr/include/readline
    /usr/local/include
    /usr/local/include/readline
    /opt/local/include
    /opt/local/include/readline
    /sw/include
    /sw/include/readline
    ENV CPATH)

find_library (LIBREADLINE_LIBRARIES
  NAMES
    readline
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBREADLINE_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibReadline "Please install the readline development package"
  LIBREADLINE_LIBRARIES
  LIBREADLINE_INCLUDE_DIRS)

mark_as_advanced(LIBREADLINE_INCLUDE_DIRS LIBREADLINE_LIBRARIES)
