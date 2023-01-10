import time
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
is_malware = ""
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
    global is_malware
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"query": "get_info","hash": hash}
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
            is_malware = "True"
            
    else:
        return f"Error: {response.text}"

def md_hash_query(hash): # queries hash in metadefender cloud
    api_key = values['md_api']
    url = f"https://api.metadefender.com/v4/hash/{hash}"
    headers = {"apikey": api_key}

    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
    # The request was successful, so you can process the response data as needed
        data = response.json()
        try:
            if data['scan_results']['scan_details']['Webroot SMD']['threat_found'] == "Malware":
                print("Malware detected by Meta Defender")
        
        except:
            if data['scan_results']['scan_all_result_a'] == "Infected":
                print("Hash match to a known malware")


        else:
        # There was an error with the request
            print('Error:', response.status_code)


def hb_hash_query(hash): #queries hash in hybrid-analysis
    global is_malware     
    api_key = values['hb_api']
    url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': api_key,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'hash': hash
    }

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        # If the status code is 200, the request was successful
        # Parse the JSON response
        data = response.json()
        for d in data:
            if d.get("verdict") == "malicious":
                is_malware="True"
        print('Sample is malicious')
    


def vt_hash_query(hash): #function to query hash in virustotal
    global is_malware
    api_key = values['vt_api']
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers={"x-apikey": api_key})
    if response.status_code == 200:
    
        file_report = response.json()
        
        # Get the number of vendors that detected the file as malicious
        num_vendors_detected_malicious = file_report["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"{num_vendors_detected_malicious} vendors detected the file as malicious.")
        is_malware = "True"
        
    else:
        print(f"An error occurred: {response.status_code}")
        
def vt_file_upload(file):
  # the API endpoint for uploading a file
  endpoint = "https://www.virustotal.com/api/v3/files"

  # the API key for accessing VirusTotal
  # (you will need to sign up for an API key at https://www.virustotal.com/gui/join-us)
  api_key = values['vt_api']

  # the file to be uploaded
  file = open(file, "rb")

  # the headers for the API request
  headers = {"x-apikey": api_key}

  # the data for the API request
  data = {"file": file}

  response = requests.post(endpoint, headers=headers, files=data)
  # check the status code of the response
  if response.status_code == 200:
    result = response.json()

      # get the scan results for the file
  analysis_id = result['data']['id']

  scan_results_endpoint = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
 
  print("Waiting for 30 second for letting the file be analyzed by various antivirus product")
  time.sleep(30 )
  # send the API request to retrieve the scan results
  response = requests.get(scan_results_endpoint.format(analysis_id=analysis_id), headers=headers)
  # check the status code of the response
  if response.status_code == 200:
      # if the request was successful, parse the response data
      response_data  = response.json()

      # get the scan results for the file
      scan_results = response_data['data']['attributes']['results']

    # initialize a counter for the number of malicious scan results
      malicious_count = 0
      total_av_count = 0

    # iterate through the scan results
      for engine, result in scan_results.items():
        # check if the file was marked as malicious by this engine
        total_av_count +=1
        if result['category'] == 'malicious':
            # increment the counter
            malicious_count += 1

      if total_av_count >= 0:
        print(f"{malicious_count} out of {total_av_count} vendor detected file as malicious")
      else:
        print('Not Detected as Malware in VT')



def hash_calc(path): #function to calculate file hash when path is provided
    with open(path, 'rb') as f:
        data = f.read()
    hash = hashlib.sha256(data).hexdigest()
    md_hash_query(hash)
    hb_hash_query(hash)
    vt_hash_query(hash)
    mb_query(hash)

def proc_path_name(process): # Find the process's path with the given process name
    for proc in psutil.process_iter():
        if proc.name() == process:
            hash_calc(proc.exe())
            break
    else:
        print('Process not found')


def proc_path_pid(pid): #This function takes process id and returns process paths
    proc = psutil.Process(pid)
    hash_calc(proc.exe())

def proc_stop_id(pid): #this function stops running process whenever a process id argument is detected and running process is malicious
    # Get the process object
    process = psutil.Process(pid)

    # Terminate the process
    process.terminate()

def proc_stop_procname(process): # this function terminates process ig given process is detected as malicious
    # Get a list of all processes with the specified name
    processes = [p for p in psutil.process_iter() if p.name() == process]

    # Terminate each process in the list
    for process in processes:
        process.kill()

def main_sec(): #function to handle various commandline arguments to query in TI sites
    
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--hash":
            fhash = sys.argv[i + 1]
            start_time= time.time()

            md_hash_query(fhash)
            hb_hash_query(fhash)
            vt_hash_query(fhash)
            mb_query(fhash)
            end_time = time.time()
            print("total time :", end_time - start_time)

        if sys.argv[i] == "--path":
            fpath = sys.argv[i + 1]
            hash_calc(fpath)

        if sys.argv[i] == "--process":
            fprocess = sys.argv[i + 1]
            proc_path_name(fprocess)
            if is_malware == "True":
                proc_stop_procname(fprocess)
        

        if sys.argv[i] == "--pid":
            fpid = int(sys.argv[i + 1])
            proc_path_pid(fpid)
            if is_malware == "True":
                proc_stop_id(fpid)

        if sys.argv[i] == "--file-upload":
            fupload = sys.argv[i + 1]    
            vt_file_upload(fupload)


main_sec()
