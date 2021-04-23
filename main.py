import  properties
import json
import time
import requests
import hashlib
import sys

def printResult(file, response): #This is a printing function to display the scan result in desired format
    print("------------------Result------------------")
    print("filename: ", file)
    print("overall_status: ", response["scan_results"]["scan_all_result_a"])
    scans = response["scan_results"]["scan_details"]
    for i in scans:
        print("engine: ", i)
        if scans[i]["threat_found"]:
            print("threat_found: ", scans[i]["threat_found"])
        else:
            print("threat_found: None")
        print("scan_result: ", scans[i]["scan_result_i"])
        print("def_time: ", scans[i]["def_time"])

if len (sys.argv) < 2:
    print("ERROR! Please specify the target file.")
    print("For example: python3 main.py <FILE_NAME> \n")
elif len(sys.argv) > 2:
    print("ERROR! Too many files provided. Please submit only single file.")
    print("For example: python3 main.py <FILE_NAME> \n")
else:
    with open(sys.argv[1], "rb") as data: #We read the file in "rb" mode because update function below take only bytes-like object
        line = data.read()
    encoded = hashlib.sha256(line).hexdigest() #This will give string conatining only hexadecimal digits

    response = requests.get(url=properties.getByHash + encoded, headers = {'apikey':properties.api_key}) #Checking if SHA256 hash is present in OPSWAT database

    if response.status_code != 200:
        response = response.json()
        print("Hash not found!")
        print("Uploading "+sys.argv[1]+" hash to OPSWAT database....")

        with open(sys.argv[1],"rb") as data:
            line = data.read()
            response = requests.post(url=properties.fileUpload, headers = {'apikey':properties.api_key, 'content-type':'application/octet-stream'}, data = line) #Uploading the file to OPSWAT
            response.raise_for_status()
            responseJson = response.json()

            data_id = responseJson['data_id']

            while True:
                response = requests.get(url=properties.getByID + data_id, headers = {'apikey':properties.api_key})
                response.raise_for_status()
                responseJson = response.json()

                if responseJson["scan_results"]["progress_percentage"] == 100: #Checking the condition if scanning completed to 100%
                    break
                print("Scanning... ", responseJson["scan_results"]["progress_percentage"])
                time.sleep(5) #To avoid excessive API calls
            print("Done!")
            printResult(sys.argv[1], responseJson)
    else:
        print("Hash Found!")
        response = response.json()
        printResult(sys.argv[1], response)





