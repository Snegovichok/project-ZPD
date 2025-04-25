FROM python:3.9-slim

WORKDIR /app

COPY . .

RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 5000
# В продакшене использовать secure_app.py
CMD ["python", "vulnerable_app.py"]

