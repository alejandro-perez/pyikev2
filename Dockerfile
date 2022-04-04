FROM debian:11

RUN apt-get -y update
RUN apt-get install -y python3-pip
RUN pip3 install netifaces pyyaml
RUN apt-get install -y ncat
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /code
WORKDIR /code
ENV CONFIG=config.yaml
ENV EXTRA_PARAMS=""
CMD set -x \
    && ncat -e /bin/cat -k -t  -l 23 & \
    python3 pyikev2.py -c $CONFIG $EXTRA_PARAMS

