
---------------------------------------------------------------
<h2> Python - Opswat Assesment - Nischith Javagal Panish </h2>
---------------------------------------------------------------

1. Install Python and pip using the link(https://www.python.org/downloads/release/python-394/) and downloading the latest version OR using the following commands: 
sudo apt-get install python
AND
sudo apt install python3-pip


2. This project uses the python-dotenv library to read data from the command line into the program, and the requests library to make the necessary REST calls. Install requests and dotEnv by running:
pip install requests 
OR 
python -m pip install requests 
AND
pip install python-dotenv 
OR  
to install ALL the requirements for this project to run successfully, you can just run this command:  
pip install -r requirements.txt 


3. Add your API key into a .env file in your root directory, from where you are running the python program and name it props.env. Enter your API Key in the following format: 
 API_KEY=<ENTER YOUR API KEY HERE>


4. Run the program using the following command: 
python opswat-nischith.py <filename/filepath>

where <filepath/filename> is the name or the path of the file you want to upload to check for malware. 
This filename can be an absolute path or a relative path(relative to the root)



