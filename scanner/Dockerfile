FROM amazonlinux:2023

RUN dnf update -y && \
    dnf install -y python3 python3-pip wget tar gzip && \
    dnf clean all

RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz | \
    tar -xz -C /usr/local/bin trivy

RUN pip3 install --no-cache-dir boto3 psycopg2-binary

WORKDIR /app

COPY scanner.py .

CMD ["python3", "scanner.py"]
