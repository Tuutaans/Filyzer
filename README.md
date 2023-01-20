# Filyzer
Just a simple python program with integration of four threat intelligence platform that allows users to query hash and upload file in those platforms.

To use this utility without any error first API keys must be loaded, see below guide. 

For displaying help:
Execute the program: python .\filyzer.py
With help switch: python .\filyzer.py –help
Just a simple python program with integration of four threat intelligence platform that allows users to query hash and upload file in those platforms.

To use this utility without any error first API keys must be loaded, see below guide. 

For displaying help:
Execute the program: python .\filyzer.py
With help switch: python --help

Loading API keys for the first time
python .\filyzer.py --vt-api {virus_total_api} --md-api {metadefender_api} --mb-api {malwarebazaar_api} --hb-api {hybrid_analysis_api}

Querying a file hash
python .\filyzer.py --hash {hash}

Providing path as an input to query the file through file's hash
python .\filyzer.py --path C:\Users\tester\mal.exe

Providing process name as an input
python .\filyzer.py --process mimikatz.exe

Providing process id name as an input
python .\filyzer.py --pid 1234

Uploading file for analysis
python .\filyzer.py --file-upload file

Loading API keys for the first time
python .\filyzer.py --vt-api {virus_total_api} --md-api {metadefender_api} --mb-api {malwarebazaar_api} --hb-api {hybrid_analysis_api}

Querying a file hash
python .\filyzer.py --hash {hash}

Providing path as an input to query the file through file's hash
python .\filyzer.py --path C:\Users\tester\mal.exe

Providing process name as an input
python .\filyzer.py --process mimikatz.exe

Providing process id name as an input
python .\filyzer.py --pid 1234

Uploading file for analysis
python .\filyzer.py --file-upload file


