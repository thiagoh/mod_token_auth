#!/bin/bash


sudo rm utils.o mod_token_auth.o
sudo rm utils.lo mod_token_auth.lo
sudo rm utils.slo mod_token_auth.slo

sudo apxs -I /home/thiago/dev/cpp/mod_token_auth/ -i -a -l cryptoc -l ssl -l crypto -n mod_token_auth -c mod_token_auth.c utils.c
