FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography
COPY iot.py .
CMD ["python", "-u", "iot.py"]
