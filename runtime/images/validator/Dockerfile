FROM python:3.12-slim
RUN pip install --no-cache-dir paramiko psycopg2-binary
WORKDIR /app
COPY . /app
ENTRYPOINT ["python", "-m", "tools.validate", "--world", "/app/world.json", \
            "--web-base", "http://web-dmz-01:8080", "--api-base", "http://api:8000"]
CMD ["--full"]
