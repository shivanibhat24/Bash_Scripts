echo"Enter the File Name:"
read fname
if [-f fname]
then 
  if [-w $fname]
  then 
     echo"Type matter to append. Press Ctrl+D to quit."
     cat >>$fname
  else
     echo"Permission to write denied."
  fi
fi
