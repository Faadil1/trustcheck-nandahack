FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py receipts.py SKILL.md ./
ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
# Provide keys at runtime via env/secret: TRUSTCHECK_ACTIVE_KEY_ID + TRUSTCHECK_ACTIVE_PRIVATE_B64U
CMD ["python3", "app.py"]
