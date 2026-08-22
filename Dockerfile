FROM python:3.11-slim

# nmap is installed explicitly here (unlike install.sh) because the
# container image is expected to be a complete, ready-to-run environment.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY aeptf ./aeptf
COPY configs ./configs

RUN pip install --no-cache-dir -e .

ENV AEPTF_CONFIG_FILE=/app/configs/default.yml

EXPOSE 8000

CMD ["aeptf", "serve"]
