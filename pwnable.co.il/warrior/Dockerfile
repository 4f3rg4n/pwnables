# sudo docker build -t warrior .
# sudo docker run -d -p 9012:1024 --rm -it warrior

FROM ubuntu:20.04

RUN apt-get update

RUN useradd -d /home/warrior/ -m -p warrior -s /bin/bash warrior
RUN echo "warrior:warrior" | chpasswd

WORKDIR /home/warrior

COPY warrior .
COPY flag .
COPY ynetd .
COPY libc-2.23.so .
COPY ld-2.23.so .

RUN chown -R root:root /home/warrior

USER warrior
EXPOSE 1024
CMD ["./ynetd", "-p", "1024", "./warrior"]
