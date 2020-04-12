# Build static binary with alpine. Use edge since the libelf-static only exists on edge.

FROM alpine:edge

RUN apk add \
  git \
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
  linux-headers

ADD . /ipftrace2
WORKDIR /ipftrace2
RUN mkdir build && cd build && cmake -DSTATIC_LINKING=1 -DSTATIC_LIBC=1 ../ && make
