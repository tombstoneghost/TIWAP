FROM python:3.8.2-slim

WORKDIR /app
COPY . /app

RUN pip3 install -r requirements.txt

# EXPOSE 5001

# ENTRYPOINT ["python"]
# CMD ["app.py"]
