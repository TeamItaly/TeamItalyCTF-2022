FROM zxgio/pwnpeii:focal-20210416

RUN sed -ie 's/sudo -H -u/sudo -H -E -u/' /pwnpeii/scripts/runner.sh

COPY main /home/problemuser/binary