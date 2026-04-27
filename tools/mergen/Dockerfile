FROM ubuntu:22.04

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsb-release wget software-properties-common gnupg \
    cmake git curl ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# LLVM 18
RUN wget -q https://apt.llvm.org/llvm.sh && chmod +x llvm.sh \
    && ./llvm.sh 18 && rm llvm.sh

# Rust (required by Mergen)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Clang symlinks
RUN ln -sf /usr/bin/clang-18 /usr/bin/clang \
    && ln -sf /usr/bin/clang++-18 /usr/bin/clang++
ENV CC=/usr/bin/clang
ENV CXX=/usr/bin/clang++

# Clone and build Mergen
RUN git clone --recursive https://github.com/NaC-L/Mergen.git /opt/mergen
WORKDIR /opt/mergen/build
RUN cmake .. && cmake --build . -j $(nproc)

# Symlink lifter binary to PATH
RUN ln -sf /opt/mergen/build/lifter /usr/local/bin/lifter

WORKDIR /work
ENTRYPOINT ["lifter"]
