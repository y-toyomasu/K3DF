FROM python:3.11-alpine

WORKDIR /app

# Newer OpenAI SDK releases require jiter, which has no Rust build target for
# Python 3.11 on ARMv7 Alpine (musl).  This OpenAI SDK release supports the
# OpenAI-compatible Moonshot API while retaining an ARMv7-friendly dependency set.
RUN pip install --no-cache-dir "openai==1.35.7" "pydantic<2"

COPY *.py ./

CMD ["python", "service.py"]
