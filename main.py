# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import json

import requests
import hashlib
import sys


def printResult(file, response):
    print("------------------Result------------------")
    print("filename: ", file)
    print("overall_status: ", response["scan_results"]["scan_all_result_a"])
    scans = response["scan_results"]["scan_details"]
    # print("scans = ", scans)
    for i in scans:
        print("engine: ", i)
        if scans[i]["threat_found"]:
            print("threat_found: ", scans[i]["threat_found"])
        else:
            print("threat_found: None")
        print("scan_result: ", scans[i]["scan_result_i"])
        print("def_time: ", scans[i]["def_time"])

sha256 = hashlib.sha256()
api_key = "<Enter your own api_key>"
if len (sys.argv) < 2:
    print("ERROR! Please specify the target file.")
    print("For example: python3 main.py <FILE_NAME> \n")
elif len(sys.argv) > 2:
    print("ERROR! Too many files provided. Please submit only single file.")
    print("For example: python3 main.py <FILE_NAME> \n")
else:
    with open(sys.argv[1], "rb") as data:
        while True:
            line = data.read()
            if not line:
                break
            sha256.update(line)
    encoded = sha256.hexdigest()
    # print("encoded = ",encoded)


    response = requests.get("https://api.metadefender.com/v4/hash/" + encoded, headers = {'apikey':api_key}).json()
    # print("response = ", response["appinfo"])

    if len(response) < 2:
        print("Hash not found!")
        print("Uploading "+sys.argv[1]+" hash to OPSWAT database....")
        with open(sys.argv[1],"rb") as data:
            response = requests.post(url='https://api.metadefender.com/v4/file', headers = {'apikey':api_key}, files = {'file':data}).json()
            data_id = response['data_id']
            print("Scanning....")
            while True:
                response = requests.get(url='https://api.metadefender.com/v4/file/' + data_id, headers = {'apikey':api_key}).json()
                if "scan_results" not in response or response["scan_results"]["progress_percentage"] == 100:
                    break

                print("Done!")
                printResult(sys.argv[1], response)
    else:
        print("Hash Found!")
        printResult(sys.argv[1], response)





