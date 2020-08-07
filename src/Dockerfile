FROM ubuntu:18.04

USER root

ENV LC_ALL C.UTF-8

ENV LANG c.UTF-8

RUN apt-get update && \
    apt-get install -y software-properties-common

RUN add-apt-repository universe

RUN apt-get update && \
    apt-get install -y python3.6 python3-pip

COPY ./spell-check /app/src/spell-check

COPY ./sqlite3 /app/src/sqlite3

COPY ./templates /app/src/templates

COPY ./__init__.py /app/src/__init__.py

COPY ./app.py /app/src/app.py

COPY ./myForms.py /app/src/myForms.py

COPY ./myModels.py /app/src/myModels.py

COPY ./requirements.txt /app/src/requirements.txt

WORKDIR /app/src

RUN pip3 install -r requirements.txt

WORKDIR /app/src/spell-check

RUN chmod 777 a.out

ENV PATH $PATH:/app/src

ENV PYTHONPATH /app/src

WORKDIR /app/src

ENV FLASK_APP app.py

ENV FLASK_RUN_HOST 0.0.0.0

WORKDIR /app/src

CMD ["flask", "run"]

