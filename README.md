# OPSWAT-Assessment
This is simple python program to scan a file against OPSWATs metadefender.opswat.com API. I used python 3.8 environment and successfully run and tested the program on both Ubuntu 18.04 and Windows. I also used -sys, -hashlib, -requests packages.

# How to execute the program
The project structure consists of two files i.e main.py and dummy.txt. The file main.py defines the main logic and dummy.txt is sample file to be tested. In the main.py file for "api_key" variable you can provide your own api key. 
* step 1: Clone the repo in your system. Open the terminal and go inside the directory where main.py and dummy are present.
* Step 2: Now write 'python3 main.py dummy' command on your terminal and hit enter. If you want to give your own file for scanning then use 'python3 main.py <FILE_NAME>' command. File  must be present in your directory.
* Step 3: The desired scan result will be print on the terminal. It may take some time because of network latency.

# Methodology
My approach is very closely related to whatever mentioned in the problem statement.
1. Calculate the hash(sha256) of given dummy.txt file using the functions in hashlib package
2. Perform a hash lookup against metadefender.opswat.com and see if their are previously cached results for the file. Basically the program will try to send get request to OPSWAT api with hash code of dummy file
3. If result found then directly call printResult function and print the scan result
4. If the hash code is not found then the given file will be uploaded to the OPSWAT api via POST request
5. After uploading the file, the program will gain ping the OPSWAT api to get scan result of recently uploaded file
6. Once the scan is complete again call printResult function for printing the scan result
