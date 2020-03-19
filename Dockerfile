FROM fedora:latest
RUN dnf -y install make llvm clang vim-common
WORKDIR /ipftrace2
ENTRYPOINT ["make"]
