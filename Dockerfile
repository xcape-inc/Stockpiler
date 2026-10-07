FROM python:3.12-slim
WORKDIR /opt/stockpiler
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git jq && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY stockpiler ./stockpiler
COPY stockpiler.sh ./stockpiler.sh
EXPOSE 8092
ENTRYPOINT ["python", "-m", "stockpiler.api"]
