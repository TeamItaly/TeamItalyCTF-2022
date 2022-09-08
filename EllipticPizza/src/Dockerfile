FROM sagemath/sagemath

USER root

WORKDIR /app

COPY ./sources.list /etc/apt/sources.list

RUN apt-get update
RUN apt-get install -y socat python3-pip gcc g++ make libffi-dev openssl libssl-dev
COPY ./requirements.txt .
#RUN pip3 install -r requirements.txt
RUN sage -pip install -r requirements.txt

COPY ./secret.py .
COPY ./source.sage .

ENTRYPOINT ["socat", "-t", "900", "-T", "120", "TCP4-LISTEN:5555,reuseaddr,fork", "EXEC:env PYTHONUNBUFFERED=1 sage source.sage"]
