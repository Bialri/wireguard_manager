FROM ubuntu:latest
LABEL authors="egor"

RUN apt-get update
RUN apt-get install iproute2 -y
RUN apt-get install wireguard -y
RUN apt-get install python3.11 python3-pip -y

WORKDIR /tests
COPY ./tests/requirements_test.txt /tests/

RUN python3.11 -m pip install -r requirements_test.txt

ENTRYPOINT ["pytest"]


