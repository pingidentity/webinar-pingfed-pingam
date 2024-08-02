#!/bin/bash

# This script generates an initial .env file. The .env file is referenced by docker compose and 'initialize-dev-tls-keypair.sh'.

mv -f .env dev/.env.bak

cp ./dev/.env_template .env

# create the private keys secret
#
secret=$(openssl rand -base64 32 | tr -d '=' | tr -d '/' | tr -d '+')
printf "\nSSL_PWD=${secret}" >> .env