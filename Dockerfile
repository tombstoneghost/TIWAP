FROM ubuntu:18.04

WORKDIR /app
COPY . /app

RUN apt-get update
RUN apt-get install iputils-ping -y
RUN apt install python3 python3-pip -y
RUN pip3 install -r requirements.txt

# EXPOSE 5001

# ENTRYPOINT ["python"]
# CMD ["app.py"]
