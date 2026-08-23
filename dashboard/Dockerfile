FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .
COPY templates ./templates

EXPOSE 8888

CMD ["python", "app.py"]
