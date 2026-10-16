# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Install the project into `/app`
WORKDIR /app

# 可按部署网络选择镜像源；默认保留 Debian 官方源。
ARG DEBIAN_MIRROR=deb.debian.org

# 保留下载缓存，网络重试或重建时复用软件包；所有系统依赖只安装一次。
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eu; \
    if [ "$DEBIAN_MIRROR" != "deb.debian.org" ]; then \
      sed -i \
        -e "s|http://deb.debian.org|https://${DEBIAN_MIRROR}|g" \
        -e "s|https://deb.debian.org|https://${DEBIAN_MIRROR}|g" \
        -e "s|http://security.debian.org|https://${DEBIAN_MIRROR}|g" \
        -e "s|https://security.debian.org|https://${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources; \
    fi; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30; \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    python3-dev

# 锁定依赖已提供常用 Linux 架构的预编译 wheel，默认不下载 Rust 工具链。
# 只有确实需要从 Rust 源码构建依赖时，才显式传入 true。
ARG INSTALL_RUST_TOOLCHAIN=false
RUN if [ "$INSTALL_RUST_TOOLCHAIN" = "true" ]; then \
      curl --proto '=https' --tlsv1.2 --connect-timeout 15 --retry 3 -fsS \
        https://sh.rustup.rs -o /tmp/rustup-init.sh \
      && sh /tmp/rustup-init.sh -y --profile minimal \
      && rm /tmp/rustup-init.sh; \
    fi

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Disable bytecode transfer during compilation to avoid EMFILE during build on low nofile limits
ENV UV_COMPILE_BYTECODE=0

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

ENV UV_PYTHON_INSTALL_MIRROR=https://registry.npmmirror.com/-/binary/python-build-standalone

# Copy dependency files first
COPY server/pyproject.toml server/uv.lock ./

# Install the project's dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
COPY server/ /app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

RUN uv run pybabel extract -F babel.cfg -o messages.pot .  && \
    (test -f lang/zh_CN/LC_MESSAGES/messages.po || uv run pybabel init -i messages.pot -d lang -l zh_CN) && \
    uv run pybabel compile -d lang -l zh_CN


# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Copy and make the start script executable
COPY server/start.sh /app/start.sh
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

# Make Celery scripts executable
RUN sed -i 's/\r$//' /app/celery/worker/start && chmod +x /app/celery/worker/start
RUN sed -i 's/\r$//' /app/celery/beat/start && chmod +x /app/celery/beat/start

# 版本信息通过构建参数传入，源码压缩包部署也不再依赖 .git。
ARG SERVER_CODE_HASH=unknown
RUN echo "EIGENT_SERVER_GIT_COMMIT=${SERVER_CODE_HASH}" > /app/.image_env

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

EXPOSE 5678

# Use the start script
CMD ["/app/start.sh"]
