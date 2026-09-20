FROM python:3.12-slim
WORKDIR /app
COPY requirements-control.txt .
RUN pip install --no-cache-dir -r requirements-control.txt
COPY . .
CMD ["uvicorn", "control.api:app", "--host", "0.0.0.0", "--port", "8000"]
