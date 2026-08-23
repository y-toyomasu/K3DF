FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir "openai>=1.0,<2.0"

COPY *.py ./

CMD ["python", "service.py"]
