#!/bin/bash

./apxs-build.sh 

sudo service apache2 restart 

tail -f /var/log/apache2/error.log
