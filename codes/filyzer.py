import zipfile
import time
import sys
import requests
import json
import hashlib
import psutil
import os
import re
import pyfiglet

#declared required variable 
fupload =""
vt_api =""
mb_api = ""
md_api = ""
hb_api =""
fpath=""
fprocess=""
fpid=""
fhash=""
is_malware = ""
values = {} #storing api saved in a file

file_path = ".\\api_list.txt"
try:
    if os.path.getsize(file_path) > 0:
        with open(".\\api_list.txt", "r") as f:
            for line in f:
                key, value = line.strip().split("=")
                values[key] = value

except:  
    if len(values) == 0:
        with open(".\\api_list.txt","w") as f:
            for i in range(len(sys.argv)):
                if sys.argv[i] == "--vt-api": # virus total api
                    vt_api = sys.argv[i + 1]
                    f.write(f"vt_api={vt_api}\n")

                if sys.argv[i] == "--mb-api": # malware bazaar api
                    mb_api = sys.argv[i + 1]
                    f.write(f"mb_api={mb_api}\n")

                if sys.argv[i] == "--md-api": #metadefender api
                    tr_api = sys.argv[i + 1]
                    f.write(f"md_api={md_api}\n")

                if sys.argv[i] == "--hb-api": #hybrid analysis api
                    otx_api = sys.argv[i + 1]
                    f.write(f"hb_api={hb_api}\n")


def mb_query(hash): #function to query a hash in malwarebazaar
    cache_file = f"{hash}_mb.pkl"
    
    # Check if the response has been cached
    if os.path.exists(cache_file):
        # Load the cached response from the file
        with open(cache_file, "r") as f:
            response = f.read()
            match = re.search(r"query_status\S:.*ok\S", str(response))
            if match:
                return "Malware"

    else:
        # Make a new request to MalwareBazaar
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"query": "get_info","hash": hash}
        headers["Authorization"] = f"Token {values['mb_api']}"
        try:
            response = requests.post(url, data=headers)
            # Save the response to the cache file
            with open(cache_file, "wb") as f:
                f.write(response.content)
        except Exception as e:  
            print(e)
            return False
    
        if response.status_code == 200:
            response = json.loads(response.text)
            if response['query_status'] == "hash_not_found":
                return False
            elif response['query_status'] == "http_post_expected":
                return False
            elif response['query_status'] == "illegal_hash":
                return False
            elif response['query_status'] == "no_hash_provided":
                return False
            elif response['query_status'] == "no_results":
                return False
            else:
                if response['query_status'] == "ok":
                    return "Malware"
                return False

        else:
            print(f"An error occurred while querying MalwareBazaar: {response.status_code}")
            return False

def md_hash_query(hash):
    """
    Queries MetaDefender Cloud for information about a file with the given hash.
    
    Args:
        hash (str): The hash of the file to be analyzed.
        
    Returns:
        bool: True if the file is detected as malicious by MetaDefender Cloud, False otherwise.
    """
    
    api_key = values['md_api']
    cache_file = f"{hash}_md.pkl"
    
    # Check if the response has been cached
    if os.path.exists(cache_file):
        # Load the cached response from the file
        with open(cache_file, "r") as f:
            response = json.load(f)
            match = re.search(r"scan_all_result_a.*I|infected.*", str(response))
            if match:
                return "Malware"
    
        # Make a new request to MetaDefender Cloud
    url = f"https://api.metadefender.com/v4/hash/{hash}"
    headers = {"apikey": api_key}
    try:
        response = requests.request("GET", url, headers=headers)
        # Save the response to the cache file
        with open(cache_file, "wb") as f:
            f.write(response.content)

    except Exception as e:
        print(e)
        return False
    if response.status_code == 200:
        # The request was successful, so you can process the response data as needed
        data = response.json()
        try:
            if data['scan_results']['scan_details']['Webroot SMD']['threat_found'] == "Malware":
                return "Malware"
        except:
            if "Infect" in data['scan_results']['scan_all_result_a'] or "infect" in data['scan_results']['scan_all_result_a']: 
                return "Malware"
        
    else:
        # There was an error with the request
        print(f"An error occurred while querying MetaDefender Cloud: {response.status_code}")
        return False


def hb_hash_query(hash): #queries hash in hybrid-analysis
    """
    Queries Hybrid Analysis for information about a file with the given hash.
    
    Args:
        hash (str): The hash of the file to be analyzed.
        
    Returns:
        bool: True if the file is detected as malicious by Hybrid Analysis, False otherwise.
    """
    api_key = values['hb_api']
    cache_file = f"{hash}_hb.pkl"
    
    # Check if the response has been cached
    if os.path.exists(cache_file):
        # Load the cached response from the file
        with open(cache_file, "rb") as f:
            response = json.load(f)
            for d in response:
                if d.get("verdict") == "malicious":
                    return "Malware"
    
    else:
        # Make a new request to Hybrid Analysis
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
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
            try:
                # Save the response to the cache file
                with open(cache_file, "w") as f:
                    json.dump(data,f)
            except Exception as e:
                print(e)
                return False

            for d in data:
                if d.get("verdict") == "malicious":
                    return "Malware"
            return False
        else:
            # There was an error with the request
            print(f"An error occurred while querying Hybrid Analysis: {response.status_code}")
            return False


def vt_hash_query(hash): #function to query hash in virustotal
    api_key = values['vt_api']
    cache_file = f"{hash}_vt.pkl"
    
    # Check if the response has been cached
    if os.path.exists(cache_file):
        # Load the cached response from the file
        with open(cache_file, "rb") as f:
            response = json.load(f)
            match = re.search(r"malicious.*\d+,", str(response))
            if response['malicious'] > 0:
                return "Malware"
    
    else:
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers={"x-apikey": api_key})
            
        except Exception as e:
            print(e)
            return False

        if response.status_code == 200:
        
            file_report = response.json()
            
            # Get the number of vendors that detected the file as malicious
            num_vendors_detected_malicious = file_report["data"]["attributes"]["last_analysis_stats"]["malicious"]
            # Save the response to the cache file
            with open(cache_file, "w") as f:
                json.dump(file_report["data"]["attributes"]["last_analysis_stats"], f)

            if int(num_vendors_detected_malicious) > 0:
                return "Malware"
            
        else:
            print(f"An error occurred: {response.status_code}")
            return False
        
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
 
  print("Waiting for 1 minute for letting the file be analyzed by various antivirus product")
  time.sleep(60)
  print('The analysis time of file may vary so re-run the command')
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
    return [md_hash_query(hash), hb_hash_query(hash), vt_hash_query(hash), mb_query(hash)]

def file_isolate(path):
    file_opt = hash_calc(path)  
    if "Malware" in file_opt:
       
        # get the file name from the path
        file_name = path.split('\\')[-1]

        # create a zip file
        with zipfile.ZipFile(file_name.split('.')[0] + '.zip', 'w') as archive:
            archive.write(path)
        os.remove(path)
        
        print("File moved to isolate directory")

def proc_path_name(process): # Find the process's path with the given process name
    for proc in psutil.process_iter():
        if proc.name() == process:
            if "Malware" in hash_calc(proc.exe()):
                proc_stop_procname(process)
            break
    else:
        print('Process not found')


def proc_path_pid(pid): #This function takes process id and returns process paths
    proc = psutil.Process(pid)
    if "Malware" in hash_calc(proc.exe()):
        proc_stop_id(pid)


def proc_stop_id(pid): #this function stops running process whenever a process id argument is detected and running process is malicious
    # Get the process object
    process = psutil.Process(pid)

    # Terminate the process
    process.terminate()
    print(f"PID {pid} stopped")

def proc_stop_procname(process): # this function terminates process ig given process is detected as malicious
    # Get a list of all processes with the specified name
    processes = [p for p in psutil.process_iter() if p.name() == process]

    # Terminate each process in the list
    for process in processes:
        process.kill()
        print(f"{process.name()} process killed")

def help_func():
    print(pyfiglet.figlet_format('Filyzer'))
    print('''
    --hash  Takes hash values as an argument. Print "Malware" if detected as malware in any platform else "None" will be printed 
    --path  Takes path of an file as an argument, and retrieve the file hash
    --process   Takes process name as an argument, and if found as malicious terminates the process
    --pid   Takes process id as an argument 
    --file-upload   Uploads file to VirusTotal for analysis
    --cache-clean   Deletes cached file
    --vt-api    loads VirusTotal API
    --hb-api    loads Hybdir Analysis API
    --md-api    loads MetaDefender API
    --mb-api    loads MalwareBazaar API
    ''')

def main_sec(): #function to handle various commandline arguments to query in TI sites
    if len(sys.argv) <= 1:
        help_func()

    for i in range(len(sys.argv)):
        if sys.argv[i] == "--hash":
            fhash = sys.argv[i + 1]
            print(md_hash_query(fhash))
            print(hb_hash_query(fhash))
            print(vt_hash_query(fhash))
            print(mb_query(fhash))

        if sys.argv[i] == "--path":
            fpath = sys.argv[i + 1]
            file_isolate(fpath)
            
        if sys.argv[i] == "--process":
            fprocess = sys.argv[i + 1]
            proc_path_name(fprocess)
            

        if sys.argv[i] == "--pid":
            fpid = int(sys.argv[i + 1])
            proc_path_pid(fpid)

        if sys.argv[i] == "--file-upload":
            fupload = sys.argv[i + 1]    
            vt_file_upload(fupload)
        
        if sys.argv[i] == "--cache-clean":
            for file in os.scandir('.\\'):
                if file.name.endswith('.pkl') and file.is_file():
                    try:
                        os.unlink(file.path)
                    except OSError:
                        print("Error while deleting file: ", file.path)

        if sys.argv[i] == "--help":
            help_func()

main_sec()
