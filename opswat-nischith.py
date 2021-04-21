import requests
import os
from dotenv import load_dotenv

load_dotenv()

apikey = os.environ["API_KEY"]
print(apikey)
headers = {'apikey' : apikey }