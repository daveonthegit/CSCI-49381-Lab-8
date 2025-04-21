#!/bin/bash

# Set the server IP or hostname (remove /24)
SERVER="http://10.1.1.2"

# Number of requests
REQUESTS=1000

for ((i=1; i<=REQUESTS; i++))
do
    curl --connect-timeout 10 "$SERVER" > /dev/null 2>&1 &
    sleep 0.02
done
