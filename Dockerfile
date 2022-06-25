FROM python:3.10.5-alpine3.16

ENV PYTHONPATH=/app

WORKDIR /app

ADD ban_poll_bot /app/ban_poll_bot
ADD requirements.txt /app/

RUN : \
    && pip3 install -r requirements.txt \
    ;

RUN ln -s /app/ban_poll_bot/cmd/run.py /usr/local/bin/ban_poll_bot

CMD ["ban_poll_bot"]
