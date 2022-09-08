FROM python:3.10-alpine

RUN apk add --no-cache --update socat py3-pip gcc g++ make libffi-dev openssl-dev

WORKDIR /chal

COPY ./requirements.txt /chal/
RUN pip3 install -r requirements.txt

COPY ./server.py /chal/

ENTRYPOINT ["socat", "-t", "300", "-T", "5", "TCP4-LISTEN:5555,reuseaddr,fork", "EXEC:env PYTHONUNBUFFERED=1 python3 /chal/server.py"]