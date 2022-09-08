FROM disconnect3d/nsjail

RUN apt update && apt upgrade -y && apt install -y socat python3 python3-pip unzip

RUN /usr/sbin/adduser -h /chall --disabled-password -u 1000 user

COPY flag /

COPY nsjail.cfg /chall/

COPY requirements.txt /chall/
RUN pip3 install -r /chall/requirements.txt

COPY challenge.py /chall/

ENTRYPOINT ["socat", "TCP-LISTEN:5555,reuseaddr,fork", "EXEC:nsjail --config /chall/nsjail.cfg -- /usr/bin/python3 -u challenge.py"]
