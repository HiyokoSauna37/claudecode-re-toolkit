# ti-sample-uploader: decrypts a quarantine .enc.gz IN MEMORY and uploads it to
# MalwareBazaar / VirusTotal / Triage. The host never sees plaintext.
#
#   docker build -t ti-sample-uploader:latest tools/threat-intel/uploader
#
# Normally built/run automatically by `intel-cli.py submit run <plan_id>`.
FROM python:3.13-slim

RUN pip install --no-cache-dir "cryptography>=42" \
 && useradd -m -u 1000 uploader

COPY upload_sample.py /app/upload_sample.py

USER uploader
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "/app/upload_sample.py"]
