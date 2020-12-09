# Build static binary with alpine. Use edge since the libelf-static only exists on edge.

FROM alpine:3.12.1

RUN apk add \
  curl \
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
  readline-static \
  linux-headers

RUN curl -OL https://github.com/libbpf/libbpf/archive/v0.2.tar.gz
RUN tar xvf v0.2.tar.gz
RUN cd libbpf-0.2/src && make install BUILD_STATIC_ONLY=1

ADD . /ipftrace2
WORKDIR /ipftrace2

RUN cmake -DSTATIC_LINKING=1 -DSTATIC_LIBC=1 . && make
