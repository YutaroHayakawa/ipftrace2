# Build environment for static binary

FROM alpine:3.12.1

RUN apk add \
  git \
  xxd \
  curl \
  clang \
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

# TODO: Replace this commit SHA to tag name when it is released
RUN git clone https://github.com/libbpf/libbpf
RUN cd libbpf/src && git checkout 9e123fa5d20017923ec39b5af5f269488b7073d6
RUN cd libbpf/src && make install BUILD_STATIC_ONLY=1

RUN curl -OL http://www.lua.org/ftp/lua-5.4.2.tar.gz
RUN tar xvf lua-5.4.2.tar.gz
RUN cd lua-5.4.2 && make && make install

ADD . /ipftrace2
WORKDIR /ipftrace2

RUN cd src && make
RUN cmake -DSTATIC_LINKING=1 -DSTATIC_LIBC=1 . && make
