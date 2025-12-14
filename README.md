# Scripting-CA2
Project Overview

This project is a network recon tool developed in Python. It is designed to perform TCP port scanning against multiple targets to identify open services. The tool offers multi threaded scanning, an interactive menu and a structured output.

Requirements

socket
concurrent.futures
argparse
json and csv
logging
types

Running the code 

python recon.py
The above will run the script and you will be presented with a menu
The Other way is to use passing arguments
python recon.py scan --targets targets.txt --ports 22,80,443 --workers 50 --output my_scan

Features
Multi-Threaded scanning: Uses threadpoolexecutor to scan hundred of ports concurrently
Interactive Menu: A user friendly menu that prompts for inputs and validates data
Structured Reporting: Automatically generates reports in both JSON AND CSV
Flexible port parsing: Inteligent parsing engine that handles indivudla ports 8- lists 80,443 and ranges 1000-2000 simultaneously
Service Hinting: Identifies common services (http,https) based on standard potr mapping
Robust Error handling: Identifies socket errors,timeouts an fileI/0 issues to keep scanner running.

Reflection on project

In terms of challenges the most difficult part was identifying errors and bugs I encountered NameError and TypeError which led me to SimpleNameSpace and understanding class structures. I learned a large amount about concurrent.futures and how to manage race conditions when writing to lists.When it comes to improvements I would have liked to complete the banner grabbing and add some more features to the project altough the features I did get to finish may have not been as well implemented if I had rushed through them.

