#!/bin/bash

WORKDIR=/home/ubuntu/demo-app

systemctl stop demo-app

cd ${WORKDIR}
rm -rf ..?* .[!.]* *
