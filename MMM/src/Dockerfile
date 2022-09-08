FROM ubuntu
RUN apt-get update
RUN apt-get install -y socat
RUN mkdir -p /root/data; chown 1000:1000 /root/data
WORKDIR /root
COPY m3 .
WORKDIR /root/data
COPY flag.txt .
ENTRYPOINT socat tcp-l:1337,reuseaddr,fork EXEC:/root/m3