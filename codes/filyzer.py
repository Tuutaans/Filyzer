import sys
import requests
import json
import hashlib
import psutil
import os

#declared required variable 
fupload =""
vt_api =""
mb_api = ""
tr_api = ""
otx_api = ""
fpath=""
fprocess=""
fpid=""
fhash=""
values = {} #storing api saved in a file
try: #loading the api from a file
    with open(".\\api_list.txt", "r") as f:
        for line in f:
            key, value = line.strip().split("=")
            values[key] = value

except:  #in case of api not found in a file looking for user to provide api
    if len(values) == 0:
        with open(".\\api_list.txt","w") as f:
            for i in range(len(sys.argv)):
                if sys.argv[i] == "--vt-api":
                    vt_api = sys.argv[i + 1]
                    f.write(f"vt_api={vt_api}\n")

                if sys.argv[i] == "--mb-api":
                    mb_api = sys.argv[i + 1]
                    f.write(f"mb_api={mb_api}\n")

                if sys.argv[i] == "--tr-api":
                    tr_api = sys.argv[i + 1]
                    f.write(f"tr_api={tr_api}\n")

                if sys.argv[i] == "--otx-api":
                    otx_api = sys.argv[i + 1]
                    f.write(f"otx_api={otx_api}\n")


def mb_query(hash): #function to query a hash in malwarebazaar
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"query": "get_info","hash": fhash}
    headers["Authorization"] = f"Token {values['mb_api']}"
    response = requests.post(url, data=headers)
    if response.status_code == 200:
        response = json.loads(response.text)
        if response['query_status'] == "hash_not_found":
            print("File's hash not found in MalwareBazaar")
        elif response['query_status'] == "http_post_expected":
            print("Wrong http method")
        elif response['query_status'] == "illegal_hash":
            print("Not a Hash")
        elif response['query_status'] == "no_hash_provided":
            print("Hash not provided")
        else:
            print("Sample Found")
            if "--pid" in sys.argv:
                proc_stop_id(fpid)


    else:
        return f"Error: {response.text}"


def vt_hash_query(hash): #function to query hash in virustotal
    api_key = values['vt_api']
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{fhash}", headers={"x-apikey": api_key})
    if response.status_code == 200:
    
        file_report = response.json()
        
        # Get the number of vendors that detected the file as malicious
        num_vendors_detected_malicious = file_report["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"{num_vendors_detected_malicious} vendors detected the file as malicious.")
    else:
        print(f"An error occurred: {response.status_code}")
        
def vt_file_query(): #function to upload file in virustotal
    api_key = values['vt_api']
    
    with open(fupload, 'rb') as file:
        file_content = file.read()

        url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': api_key}
        response = requests.post(url, headers=headers, data=file_content)

        if response.status_code == 200:
            scan_results = response.json()
            print(scan_results)
        else:
            print('An error occurred:', response.status_code)


def hash_calc(path): #function to calculate file hash when path is provided
    global fhash
    with open(path, 'rb') as f:
        data = f.read()
    fhash = hashlib.sha256(data).hexdigest()
    vt_hash_query(fhash)
    mb_query(fhash)

def proc_path_name(process): # Find the process's path with the given process name
    for proc in psutil.process_iter():
        if proc.name() == fprocess:
            hash_calc(proc.exe())
            break
    else:
        print('Process not found')


def proc_path_pid(pid): #This function takes process id and returns process paths
    proc = psutil.Process(fpid)
    hash_calc(proc.exe())

def proc_stop_id(fpid): #this function stops running process whenever a process id argument is detected and running process is malicious
    # Get the process object
    process = psutil.Process(fpid)

    # Terminate the process
    process.terminate()

def main_sec(): #function to handle various commandline arguments to query in TI sites
    global fhash
    global fpid
    global fprocess
    global fpath
    global fupload
    
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--hash":
            fhash = sys.argv[i + 1]

        if sys.argv[i] == "--path":
            fpath = sys.argv[i + 1]
            hash_calc(fpath)

        if sys.argv[i] == "--process":
            fprocess = sys.argv[i + 1]
            proc_path_name(fprocess)

        if sys.argv[i] == "--pid":
            fpid = int(sys.argv[i + 1])
            proc_path_pid(fpid)
            

        if sys.argv[i] == "--file-upload":
            fupload = sys.argv[i + 1]    


main_sec()
