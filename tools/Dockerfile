FROM ubuntu:22.04

LABEL maintainer="vivek.dutta@iopsys.eu"
LABEL build="docker build -t bbfdm-tools ."
LABEL run="docker run -it --rm -v PWD/..:/builds/bbfdm bbfdm-tools"

RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
	cmake \
	libjson-c-dev \
	libssl-dev \
        libcurl4-openssl-dev \
	pkg-config \
	libtool \
	libnl-3-dev \
	libnl-genl-3-dev \
	libnl-route-3-dev \
	autoconf \
	automake \
	autotools-dev \
	binutils \
	net-tools \
	curl \
	sudo \
        git

RUN mkdir /opt/dev

# libubox
ARG LIBUBOX_VERSION=75a3b870cace1171faf57bd55e5a9a2f1564f757
RUN \
    cd /opt/dev && \
    git clone https://git.openwrt.org/project/libubox.git && \
    cd libubox && mkdir build && cd build && \
    git checkout ${LIBUBOX_VERSION} && \
    cmake -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j2 && \
    make install

# uci
ARG UCI_VERSION=5781664d5087ccc4b5ab58505883231212dbedbc
RUN \
    cd /opt/dev && \
    git clone https://git.openwrt.org/project/uci.git && \
    cd uci && \
    git checkout ${UCI_VERSION} && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF . && \
    make -j2 && \
    make install

# ubus
ARG UBUS_VERSION=f787c97b34894a38b15599886cacbca01271684f
RUN \
    cd /opt/dev && \
    git clone https://git.openwrt.org/project/ubus.git && \
    cd ubus && \
    git checkout ${UBUS_VERSION} && \
    cmake -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF . && \
    make -j2 && \
    make install

# 1. Create new unprivileged user "dev"
# 2. Install fixuid to accomodate for the host machine UID/GID
ARG FIXUID_VERSION=0.5.1
RUN useradd -m -s /bin/bash dev && \
    curl -fsSL "https://github.com/boxboat/fixuid/releases/download/v${FIXUID_VERSION}/fixuid-${FIXUID_VERSION}-linux-amd64.tar.gz" | tar -C /usr/local/bin -xzf -

# Copy fixuid configuration
COPY docker/fixuid.yml /etc/fixuid/config.yml

# Copy git configuration to dev's home folder
COPY --chown=dev:dev docker/gitconfig /home/dev/.gitconfig

RUN echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/10-dev

ENTRYPOINT ["/usr/local/bin/fixuid", "-q"]
CMD ["bash"]

RUN mkdir -p /builds/bbf/bbfdm /home/dev/.ssh \
    && chown -R dev:dev /builds/bbf/bbfdm \
    && chown -R dev:dev /home/dev \
    && chown -R dev:dev /opt/dev \
    && mkdir -p /usr/share/bbfdm \
    && chown -R dev:dev /usr/share/bbfdm

USER dev:dev
WORKDIR /builds/bbf/bbfdm
VOLUME ["/builds/bbf/bbfdm"]
