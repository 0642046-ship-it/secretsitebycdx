FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir gunicorn==23.0.0 && useradd -u 10001 -m ramka && mkdir /data && chown ramka /data
COPY server /app/server
COPY index.html app.js style.css /app/
USER ramka
ENV RAMKA_DB=/data/ramka.db
EXPOSE 8000
CMD ["gunicorn", "--chdir", "/app/server", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "30", "app:application"]
