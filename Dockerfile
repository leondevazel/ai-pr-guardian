FROM python:3.12-slim

WORKDIR /app

# The web demo reviews diffs only, with no repository checkout, so Semgrep (hundreds of MB)
# is left out of this image.
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "anthropic>=1.7,<2" "unidiff==0.7.5"

COPY src/ src/
COPY web/ web/

ENV PYTHONPATH=/app/src:/app
EXPOSE 8000

CMD ["sh", "-c", "uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
