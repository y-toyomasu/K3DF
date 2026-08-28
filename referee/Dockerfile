FROM python:3.11-alpine
WORKDIR /app
COPY service.py ./
RUN mkdir /state && chown nobody:nogroup /state
USER nobody
CMD ["python", "service.py"]
