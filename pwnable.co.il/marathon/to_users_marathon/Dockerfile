# sudo docker build -t marathon .
# sudo docker run -d -p 9022:1024 --rm -it marathon

FROM ubuntu:20.04

RUN apt-get update

RUN useradd -d /home/marathon/ -m -p marathon -s /bin/bash marathon
RUN echo "marathon:marathon" | chpasswd

WORKDIR /home/marathon

COPY marathon .
COPY flag .
COPY ynetd .
COPY libc.so.6 .
COPY ld.so .
COPY libcrypto.so.1.1 .
COPY libdl.so.2 .
COPY libpthread.so.0 .

RUN chown -R root:root /home/marathon

USER marathon
EXPOSE 1024
CMD ["./ynetd", "-p", "1024", "./marathon"]
