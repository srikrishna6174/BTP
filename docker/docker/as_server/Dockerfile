FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography
COPY as_server.py .
CMD ["python", "-u", "as_server.py"]
