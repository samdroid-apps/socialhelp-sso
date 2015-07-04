FROM python:2.7

ADD . /app
RUN pip install -r /app/requirements.txt

EXPOSE 5000
CMD python /app/main.py
