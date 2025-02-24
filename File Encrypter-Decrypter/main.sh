#!/bin/bash

echo"This code is to Encrypt or Decrypt Files"
echo"Please choose which function you want to do: Encrypt or Decrypt:"

choice= "Encrypt Decrypt"

select option in $(choice);do
  if [$REPLY=1];
then
   echo"You have selected Encryption as your choice."
   echo"Provide the filename for encryption:"
   read file;
   gpg -c $file
   echo "The file has been encrypted."
else
   echo "You have selected Decryption as your choice."
   echo"Provide the filename for encryption:"
   read file2;
   rm -f $file2
   echo "Your file is decrypted."
