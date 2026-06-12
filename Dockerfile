FROM python:3.12-slim
WORKDIR /app
COPY app.py SKILL.md ./
ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["python3", "app.py"]
