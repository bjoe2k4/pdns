FROM centos:7
RUN yum groupinstall -y "Development Tools"
ENV packages "lua-devel which tar bzip2 curl \
     autoconf \
     automake \
     bison \
     boost-devel \
     bzip2 \
     cryptopp-devel \
     eigen3-devel \
     gcc-c++ \
     geoip-devel \
     git \
     libedit-devel \
     libsodium-devel \
     libtool \
     lmdb-devel \
     lua-devel \
     luajit-devel \
     mariadb-devel \
     mbedtls-devel \
     net-snmp-devel \
     openldap-devel \
     pandoc \
     postgresql-devel \
     protobuf-devel \
     protobuf-compiler \
     re2-devel \
     readline-devel \
     rpm-build \
     rpmdevtools \
     sqlite-devel \
     systemd-devel \
     tinycdb-devel \
     unixODBC-devel \
     yaml-cpp-devel \
     zeromq-devel"
RUN yum install -y $packages && rpm --query --queryformat "" $packages

WORKDIR /build
ADD . /build
ARG VERSION
ARG RELEASE
RUN ./build-scripts/build-auth-rpm
