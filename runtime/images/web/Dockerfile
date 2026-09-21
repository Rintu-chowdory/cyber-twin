FROM python:3.12-slim
RUN pip install --no-cache-dir flask gunicorn
WORKDIR /srv
COPY app.py .
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
