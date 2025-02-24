#! /bin/bash

#Simple Password Generator

echo"This is a a Simple Password Generator"
echo"Please enter the length of the Password:"
d PASS_LENGTH

for p in $(seq1);
do
   openssl rand -base64 48 | cut -cl-$PASS_LENGTH 
