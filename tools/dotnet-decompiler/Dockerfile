FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine

# Install .NET 6.0 runtime (required by ilspycmd 8.x)
RUN dotnet_version=6.0.36 && \
    wget -O dotnet6.tar.gz "https://dotnetcli.azureedge.net/dotnet/Runtime/$dotnet_version/dotnet-runtime-$dotnet_version-linux-musl-x64.tar.gz" && \
    tar -xzf dotnet6.tar.gz -C /usr/share/dotnet && \
    rm dotnet6.tar.gz

# Install ILSpy CLI (ilspycmd)
RUN dotnet tool install --global ilspycmd --version 8.2.0.7535

# Install Python3 for decrypt_quarantine.py
RUN apk add --no-cache python3 py3-pip py3-cryptography bash && \
    pip3 install --break-system-packages python-dotenv

# Copy quarantine decryption script
COPY decrypt_quarantine.py /opt/scripts/decrypt_quarantine.py

# Add dotnet tools to PATH
ENV PATH="${PATH}:/root/.dotnet/tools"

# Create working directories
RUN mkdir -p /analysis/input /analysis/output

WORKDIR /analysis

CMD ["sleep", "infinity"]
