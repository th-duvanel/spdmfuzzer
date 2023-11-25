#!/bin/bash

if [[ ! -f cert.pem ]] && [[ ! -f key.pem ]]; then
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -subj /C=/ST=/L=/O=/OU=/CN=
fi

openssl s_server -key key.pem -dkey key.pem -cert cert.pem -dcert cert.pem