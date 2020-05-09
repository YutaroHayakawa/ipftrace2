# Build static binary with alpine. Use edge since the libelf-static only exists on edge.

FROM alpine:edge

RUN apk add \
  cmake \
  xz-dev \
  fts-dev \
  libc-dev \
  build-base \
  zlib-dev \
  zlib-static \
  elfutils-dev \
  bzip2-dev \
  bzip2-static \
  libelf-static \
  pcre2-dev \
  readline-dev \
  linux-headers

ADD . /ipftrace2
WORKDIR /ipftrace2

RUN cmake -DSTATIC_LINKING=1 -DSTATIC_LIBC=1 . && make
