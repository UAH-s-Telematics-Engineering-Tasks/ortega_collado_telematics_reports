#!/bin/bash

# You need to install both Telegraf and InfluxDB. You may try your hand with the package manager (i.e apt) or go fo the source files...

# Get Pyhton's libraries -> Install pip3 (i.e sudo apt install python3-pip) if you don't have it yet!
pip3 install urllib3 influxdb

# Copy Telegraf's config file to the appropriate location
sudo cp telegraf.conf /etc/telegraf/telegraf.conf

# Edit the crontab (run crontab -e) and add the following line to add data every minute
# * * * * * python3 gather_data.py
