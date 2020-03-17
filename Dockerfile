FROM fedora:latest

RUN dnf -y install make llvm clang gcc zlib-devel elfutils-libelf-devel

RUN curl -OL https://git.kernel.org/torvalds/t/linux-5.6-rc5.tar.gz
RUN tar xvf linux-5.6-rc5.tar.gz
RUN cd linux-5.6-rc5/tools/lib/bpf && make -j install
RUN cd linux-5.6-rc5/tools/bpf/bpftool && make -j install

WORKDIR /ipftrace2

ENTRYPOINT ["make"]
