FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mock_backend.py .
ENV FLASK_ENV=production
CMD ["python", "mock_backend.py"]
