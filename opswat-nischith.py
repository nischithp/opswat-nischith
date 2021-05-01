import requests
import os
from requests.api import head
from dotenv import dotenv_values
import json
from time import sleep
import sys
import hashlib

status_codes = {200: "OK",
                204: "No Content",
                301: "Moved permanently",
                400: "Bad Request - There was a client error",
                401: "Not authorized - Auth failed",
                404: "Not found - Endpoint not found",
                405: "Method not allowed - CORS config missing",
                406: "Not Acceptable - Payload type not accepted",
                408: "Timeout - Request was over 60 secs",
                429: "Too Many Requests - Rate limit exceeded",
                500: "Internal Server Error - Server Error",
                501: "Not implemented - CORS method is not implemented",
                503: "Service Unavailable - 3rd party service unavailable"}

# this is used to return the values in the env file as a dictionary 
config = dotenv_values("props.env")

file_upload_url = "https://api.metadefender.com/v4/file"
file_hash_check_url = "https://api.metadefender.com/v4/hash/"

def calculateHash(filePath):
    # calculate the has of the entered file
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(filePath, 'rb') as afile:
        # only read into file of BLOCKSIZE into the memory. This helps if the files are larger and might not fit entirely into the memory at once
        # Also reading file as binary is important, as we need to ensure all types of files can be hashed and checked
        buffer = afile.read(BLOCKSIZE)
        while len(buffer) > 0:
            hasher.update(buffer)
            buffer = afile.read(BLOCKSIZE)
    print("Calculated Hash of file: ", hasher.hexdigest())
    return hasher.hexdigest()

def main(filePath):
    # check the hash of the file using the API to see if it has already been scanned
    headers = {'apikey': config["API_KEY"]}

    hashOfFile = calculateHash(filePath)
    res = requests.get(file_hash_check_url+hashOfFile, headers=headers)

    # testHash = "6A5C19D9FFE8804586E8F4C0DFCC66DE"
    # res = requests.get(file_hash_check_url+testHash, headers= headers)

    # if hash not found, a 404 is returned
    if res.status_code == 404:
        print("Hash not found on Server. Initiating file upload and scan.")

        maxFileSize = 65536
        if os.path.getsize(filePath) > maxFileSize:

            # implement buffer and multipart upload if the file size is bigger than a given number of size that we can specify - either based on our programming language constraints or security constraints
            files = {'file': open(filePath, 'rb')} 
            print("File size is bigger than expected. Implementing multi-part upload.")
            headers = {'apikey': config["API_KEY"]
                       }

            # do not specify content-type in the header if sending files using 'files' parameter. Requests library automatically recognises it as a multi-part form data
            res = requests.post(file_upload_url, headers=headers, files=files)
            if res.status_code == 200:
                res = json.loads(res.text)
            else:
                print(f"Error. Multi-part file upload has failed. Response Status Code:{res.status_code}")
        else:
            # here if the file size is greater than the buffer/memory size, we have to send multiple parts in the form data and change content-type in request headers as well
            f = open(filePath, 'rb').read()

            headers = {'apikey': config["API_KEY"],
                    'content-type': 'application/octet-stream'
                    }
            res = {}
            res = requests.post(file_upload_url, headers=headers, data=f)
            if res.status_code == 200:
                print(f"Upload initiated.")
            res = json.loads(res.text)

        # dict to hold polling results
        pollingRes = {}

        while True:
            headers = {'apikey': config["API_KEY"]
                    }
            # Check HTTP response code here before parsing as JSON
            urlString = f"{file_upload_url}/{res['data_id']}"
            pollResult = requests.get(urlString, headers=headers)
            pollingRes = json.loads(pollResult.text)

            if pollResult.status_code == 200:
                # check to see if the progress percentage field is present in the response. If it is, check to see if it is 100, then break and process the results
                if "scan_results" in pollingRes:
                    if "progress_percentage" in pollingRes["scan_results"]:
                        if pollingRes["scan_results"]["progress_percentage"] == 100:
                            print(f"Scan completed. Progress: {pollingRes['scan_results']['progress_percentage']} %")
                            break
                        else:
                            print(f"Scan in progress. Progress: {pollingRes['scan_results']['progress_percentage']} %")
                # if the status is still 'inqueue' and a progress percentage is not yet available from the response, then display where in the queue the request is
                elif "status" in pollingRes:
                    print(f" Please wait. Request in queue. Status: {pollingRes['status']}. \n You are {pollingRes['in_queue']} in queue.")

                
                print(f"File still being analysed.")
                # this sleep time can also be changed based on the file size so that we don't make too many requests for higher file sizes and too less for smaller file sizes 
                sleepTime = 0.5
                sleep(sleepTime)
                print(f"Data with data ID: {pollingRes['data_id']}  is being scanned. Please wait...")
            elif pollResult.status_code == 204:
                # we can use the status code dict created to have a switcher dedicated to handling each and every possible result from the API
                print(status_codes[pollResult.status_code])
        # once the results are obtained, print them out in the order specified
        print("filename: ", filePath)
        for i in pollingRes['scan_results']['scan_details'].keys():
            print("engine:", i)
            print("threat_found:", pollingRes['scan_results']['scan_details'][i]['threat_found'])
            print("scan_result:", pollingRes['scan_results']['scan_details'][i]['scan_result_i'])
            print("def_time:", pollingRes['scan_results']['scan_details'][i]['def_time'])


    elif res.status_code == 200:
        # if the hash was found on the server
        print("Hash of this file was found on server. Here are the details:")
        hashRes = json.loads(res.text)
        print("filename: ", filePath)
        for i in hashRes['scan_results']['scan_details'].keys():
            print("engine:", i)
            print("threat_found:", hashRes['scan_results']['scan_details'][i]['threat_found'])
            print("scan_result:", hashRes['scan_results']['scan_details'][i]['scan_result_i'])
            print("def_time:", hashRes['scan_results']['scan_details'][i]['def_time'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Please provide valid filename.')
        exit(0)
    filePath = sys.argv[1]
    main(filePath)



