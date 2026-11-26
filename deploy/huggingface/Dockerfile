# Hugging Face Space (Docker) for the IncogRx demo engine with OCR. Not part of the graded run.
# The Space holds only this file and its README: the code is cloned from the public GitHub repo,
# so a push to GitHub plus "Factory rebuild" on the Space picks up changes.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user
# re-clone whenever main moves (the ref file changes, so this layer is not reused from cache)
ADD https://api.github.com/repos/Nikitha1727/IncogRx/git/refs/heads/main /tmp/main.json
RUN git clone --depth 1 https://github.com/Nikitha1727/IncogRx.git /app \
 && pip install --no-cache-dir -r /app/demo/requirements-demo.txt \
 && chown -R user /app
WORKDIR /app
USER user
ENV TESSDATA_PREFIX=/app/demo/tessdata \
    PYTHONUNBUFFERED=1 \
    PORT=7860
EXPOSE 7860
CMD ["python", "demo/app.py", "--no-browser"]
