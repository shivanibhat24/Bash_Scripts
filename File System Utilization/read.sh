#!/bin/bash
#Script to check the utilisation of files every 120s (2mins)
do 
date >> /var/log/fs-monitor.txt
sudo df -h >> /var/log/fs-monitor.txt
sleep 120
done
