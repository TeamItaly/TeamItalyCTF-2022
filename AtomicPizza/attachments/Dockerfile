FROM ubuntu:22.04

RUN apt-get update && apt-get install socat -y && apt-get clean

RUN useradd pizza_lover

WORKDIR /home/pizza_lover
COPY atomic_pizza .
COPY flag.txt ./pizza_secret.txt

RUN chown -R root:pizza_lover .

USER pizza_lover

ENTRYPOINT socat -T 30 -d tcp-listen:12321,reuseaddr,fork exec:/home/pizza_lover/atomic_pizza,stderr