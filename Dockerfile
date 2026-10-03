FROM python:3.12-slim
WORKDIR /opt/stockpiler
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY stockpiler ./stockpiler
EXPOSE 8092
ENTRYPOINT ["python", "-m", "stockpiler.api"]
