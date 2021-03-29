FROM python:3.7.2-alpine3.7
WORKDIR /proxy
COPY . .
CMD ["/usr/local/bin/python3", "proxy.py"]