FROM archlinux

USER root

# RUN mkdir /app
WORKDIR /app

COPY flag.txt /app
COPY start.sh /app
COPY 31-kreap.rules /app
COPY chall /app
COPY kreap.ko /app
RUN chmod +x /app/start.sh
RUN chmod +x /app/chall

# Drops privileges
CMD ["/app/start.sh"]