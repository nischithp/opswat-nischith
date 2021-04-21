import requests
import os
from requests import status_codes

from requests.api import head
from dotenv import dotenv_values

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
# configure headers and get the API request ready
file_upload_url = "https://api.metadefender.com/v4/file"
file_hash_url = "https://api.metadefender.com/v4/hash/"

# check the hash of the file using the API to see if it has already been scanned 
headers = {'apikey' : config["API_KEY"] }
filePath = input("Enter the path of the file along with the extention:")

# calculate the has of the entered file
BLOCKSIZE = 65536
hasher = hashlib.md5()
with open(filePath, 'rb') as afile:
    # only read into file of BLOCKSIZE into the memory. This helps if the files are larger and might not fit entirely into the memory at once
    buf = afile.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(BLOCKSIZE)
print(hasher.hexdigest())

res = requests.get(file_hash_url+hasher.hexdigest(), headers= headers)
print("HASH CALCULATED FOR FILE: "+hasher.hexdigest())

# if hash not found, a 404 is returned
if res.status_code == 404:
    print("Hash not found on Server. Initiating file upload and scan.")
    # here if the file size is greater than the buffer/memory size, we have to send multiple parts to the server by multiple requests
    f = open(filePath, 'rb').read()
    headers = {'apikey' : config["API_KEY"],
                'file'  : f,
                'filename' : filePath }
elif res.status_code == 200:
    # if the hash was found on the server
    print(res.text)

# while(True):
#     filePath = input("Enter the path of the file along with the extention:")
#     # try:
#     f = open(filePath, 'rb')
#     # if file exists and is valid, add it to the headers
#     if f:
#         headers = {'apikey' : config["API_KEY"],
#                 'file'  : f,
#                 'filename' : filePath }
#         break
#     # if file name is invalid, raise exception 
#     else:
#         raise Exception("File does not exist. Please enter a valid name")


# res = requests.post(url, headers=headers)
# print(res.text)
# except:


