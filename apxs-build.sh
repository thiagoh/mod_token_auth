#!/bin/bash

sudo apxs -i -a -l cryptoc -l ssl -l crypto -c project/src/mod_token_auth.c 

