FROM debian:bookworm-slim

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y libpcre2-dev build-essential\
    cmake libboost-system-dev libseccomp-dev git autoconf\
    libboost-thread-dev xinetd supervisor libc6-i386
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/
RUN git clone --single-branch --branch release https://github.com/jpcre2/jpcre2
WORKDIR /tmp/jpcre2
RUN ./configure; make; make install
RUN rm -rf /tmp/jpcre2
WORKDIR /

RUN useradd -m -u 5000 ctf && mkdir /execute/
COPY ./ /execute/

RUN mv /execute/xinetd.conf /etc/xinetd.d/ctf
RUN mv /execute/chall /home/ctf/chall && \
    mv /execute/pizza_secret_recipe /home/ctf/pizza_secret_recipe && \
    mv /execute/banner.txt /home/ctf/banner.txt

RUN g++ /execute/laproxy.cpp -o /execute/proxy -O3 -lboost_system -lpcre2-8 -lboost_thread -lstdc++ -pthread

RUN echo "Your IP has exceeded its resource limit." > /etc/banner_fail \
 && chown -R root:ctf /home/ctf \
 && chown -R root:nogroup /execute \
 && chmod 750 -R /home/ctf /execute

CMD ["/usr/bin/supervisord", "-c", "/execute/supervisord.conf"]