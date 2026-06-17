FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
        "fastapi==0.111.0" \
        "uvicorn[standard]==0.30.1" \
        "psutil==5.9.8"

COPY main.py .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]