# Build environment for static binary

FROM alpine:3.12.1

RUN apk add \
  git \
  xxd \
  curl \
  clang \
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

RUN curl -OL http://www.lua.org/ftp/lua-5.4.2.tar.gz
RUN tar xvf lua-5.4.2.tar.gz
RUN cd lua-5.4.2 && make && make install
RUN rm -rf lua-5.4.2 lua-5.4.2.tar.gz

RUN git clone -b v0.8.0 https://github.com/libbpf/libbpf
RUN cd libbpf/src && make install BUILD_STATIC_ONLY=1
RUN rm -rf libbpf
