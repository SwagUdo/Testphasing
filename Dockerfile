FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libc6-dev \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    pkg-config \
    libpcre3-dev \
    zlib1g-dev \
    clang \
    llvm-dev \
    vim \
    file \
    net-tools \
    ca-certificates \
    automake \
    autoconf \
    cmake \
    && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/gcc

RUN pip3 install --no-cache-dir qiling==1.4.6

WORKDIR /opt

RUN wget -q \
        https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.03c.tar.gz \
    && tar xzf 4.03c.tar.gz \
    && mv AFLplusplus-4.03c AFLplusplus \
    && rm 4.03c.tar.gz \
    && cd /opt/AFLplusplus \
    && make -j"$(nproc)"

RUN cd /opt/AFLplusplus/unicorn_mode \
    && ./build_unicorn_support.sh || true

RUN python3 - <<'PY'
from pathlib import Path

p = next(
    Path("/root/.local/lib/python3.10/site-packages").glob(
        "unicornafl-*.egg/unicornafl/unicornafl.py"
    )
)

text = p.read_text()

needle = "import distutils"
replacement = "import distutils\nimport distutils.sysconfig"

if needle not in text:
    raise SystemExit("unicornafl.py: expected import not found")

if "import distutils.sysconfig" not in text:
    text = text.replace(
        needle,
        replacement,
        1,
    )
    p.write_text(text)

print(f"patched: {p}")
PY

WORKDIR /opt

RUN wget -q \
        http://nginx.org/download/nginx-1.18.0.tar.gz \
    && tar xzf nginx-1.18.0.tar.gz \
    && cd nginx-1.18.0 \
    && ./configure \
        --prefix=/usr \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/tmp/nginx.pid \
        --lock-path=/var/lock/nginx.lock \
        --with-select_module \
        --with-pcre \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf \
        /opt/nginx-1.18.0 \
        /opt/nginx-1.18.0.tar.gz

RUN mkdir -p /etc/nginx && \
    cat > /etc/nginx/nginx.conf <<'EOF'
worker_processes 1;

master_process off;
daemon off;

error_log stderr;

pid /tmp/nginx.pid;

events {
    worker_connections 1024;
    use select;
    multi_accept off;
}

http {
    access_log off;

    server {
        listen 127.0.0.1:8080;

        location / {
            return 200 "OK";
        }
    }
}
EOF

RUN nginx -v
RUN nginx -V 2>&1

#qiling всеми правдами и неправдами не видил просто так nginx, я его туда засунул
RUN mkdir -p /opt/rootfs && \
    cp -a /bin /opt/rootfs/ && \
    cp -a /sbin /opt/rootfs/ && \
    cp -a /lib /opt/rootfs/ && \
    cp -a /lib64 /opt/rootfs/ && \
    cp -a /usr /opt/rootfs/ && \
    cp -a /etc /opt/rootfs/
    
RUN mkdir -p \
        /opt/rootfs/tmp \
        /opt/rootfs/var/log/nginx \
        /opt/rootfs/var/lib/nginx/body \
        /opt/rootfs/var/lib/nginx/proxy \
        /opt/rootfs/var/lib/nginx/fastcgi \
        /opt/rootfs/var/lib/nginx/scgi \
        /opt/rootfs/var/lib/nginx/uwsgi \
    && touch /opt/rootfs/var/log/nginx/error.log \
    && chmod 666 /opt/rootfs/var/log/nginx/error.log \
    && chmod 777 /opt/rootfs/tmp \
    && chmod 777 /opt/rootfs/var/lib/nginx

RUN /opt/rootfs/usr/sbin/nginx \
        -t \
        -c /opt/rootfs/etc/nginx/nginx.conf

WORKDIR /work