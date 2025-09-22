FROM python:3.10-slim
WORKDIR /workspace
# pin openai to old version so ChatCompletion API works for current code
RUN pip install openai==0.28.0 asn1crypto cryptography
COPY generate_and_create.py /workspace/
