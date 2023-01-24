# filecrypt

A simple script, written in Python, for macOS. When you run this script, you must pass a parameter for the folder name. 
Then this folder will be encrypted with an AES256 and a password you specify. 
If you run this script again on the same folder and with the correct password, the folder will be decrypted again. 

You can set an alias for this script in the .zshrc config: <br>
``alias filecrypt="python3 /path/to/script.py"``

Now run the script in the console with the alias: <br>
``filecrypt [foldername]``
