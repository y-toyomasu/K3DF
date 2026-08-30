FROM python:3.11-alpine
WORKDIR /app
COPY service.py ./
RUN addgroup -g 20001 flagreaders \
    && addgroup -g 10001 referee \
    && adduser -D -H -u 10001 -G referee referee \
    && addgroup referee flagreaders
USER referee
CMD ["python", "service.py"]
