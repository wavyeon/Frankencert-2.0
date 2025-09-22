FROM python:3.10-slim
WORKDIR /workspace
RUN apt-get update && apt-get install -y openssl curl
COPY run_tests.py /workspace/

