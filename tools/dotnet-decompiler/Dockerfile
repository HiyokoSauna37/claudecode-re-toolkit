FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine

# Install ILSpy CLI (ilspycmd).
# Pinned deliberately: ilspycmd 11.x targets net10.0, which is why the base image
# is the 10.0 SDK. Older 8.x builds targeted net6.0 and needed a side-loaded
# .NET 6 runtime -- that hack is gone. Bump the base image together with this pin.
RUN dotnet tool install --global ilspycmd --version 11.0.0.9375

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
