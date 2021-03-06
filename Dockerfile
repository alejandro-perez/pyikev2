FROM debian:10

RUN apt-get -y update
RUN apt-get install -y python3-pip
RUN pip3 install netifaces pyyaml
RUN apt-get install telnet
COPY . /code
WORKDIR /code
ENV CONFIG=config.yaml
ENV EXTRA_PARAMS=""
CMD python3 pyikev2.py -c $CONFIG $EXTRA_PARAMS
