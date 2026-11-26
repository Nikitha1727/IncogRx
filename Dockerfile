# Live demo website only (Render / Railway build this file). The scored pipeline is run by the
# organisers through raksha.toml and needs none of this.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r demo/requirements-demo.txt
ENV TESSDATA_PREFIX=/app/demo/tessdata \
    PYTHONUNBUFFERED=1 \
    PORT=8765
EXPOSE 8765
CMD ["python", "demo/app.py", "--no-browser"]
