FROM python:3.7-stretch

COPY ./scan2elk /root/scan2elk
WORKDIR /root/scan2elk/vulnscan-parser
RUN pip3 install -r ./requirements.txt && pip3 install .
WORKDIR /root/scan2elk
RUN pip3 install -r ./requirements.txt


CMD python3 scan2elk.py -dir /scans -project ${PROJECT}