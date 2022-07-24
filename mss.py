import argparse
import os
import whois #pip install python-whois
import socket
import json
import requests

parser = argparse.ArgumentParser(description="MSS command line tool is a script that collects commonly used tools for bug bounties.")
parser.add_argument('-t', type=str, required=True, help="Target Domain address")
parser.add_argument('-st', type=str, help="Security Trails API Key")
args = parser.parse_args()
ip = ""
domain = args.t

class bcolors:
    MAIN = '\033[95m'
    OSINT = '\033[94m'
    OKCYAN = '\033[96m'
    BANNER = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def is_registered():
    """
    A function that returns a boolean indicating
    whether a `domain_name` is registered
    """
    try:
        w = whois.whois(domain)
    except Exception:
        return False
    else:
        return bool(w.domain_name)


def OSINT():
    osintInput = input(bcolors.OSINT + "1 - WHOIS Information\n"
                                       "2 - Security Trails Search (For MX Records) \n")
    if osintInput == "1":
        whoisInfo = whois.whois(domain)
        print(whoisInfo)
        writeToFile(whoisInfo, "json", OSINT)

    elif osintInput == "2":
        stApiKey = args.st
        if not stApiKey:
            stApiKey = input("What is your Security Trails API KEY?\n"
                             "For More information visit " + bcolors.UNDERLINE + "https://docs.securitytrails.com/docs/re-generate-your-api-key\n" + bcolors.OSINT)
        stOutput = json.loads(requests.get("https://api.securitytrails.com/v1/domain/"+ domain +"?apikey=" + stApiKey, headers={"Content-Type":"application/json"}).text)
        print(stOutput)
        writeToFile(stOutput, "json", OSINT)

def writeToFile(output,format, retFunction):
    isWriteToFile = input("Do you want to write output to a file? Y or N ?\n")
    if isWriteToFile == "Y" or "y":
        filePath = input(" File NAME?\n")
        with open(filePath + "." + format, "+w") as file:
            file.write(str(output))
            file.close()
            retFunction()
    else:
        retFunction()

def assignIpAndDomain():
    print("Checking whether domain is registered or not.")
    if is_registered():
        ip = socket.gethostbyname(domain)
        print("Domain is registered..!")
    else:
        print("Provided target domain is not registered")
        exit(404)

banner = """
.   ,  ,-.   ,-.  
|\ /| (   ` (   ` 
| V |  `-.   `-.  
|   | .   ) .   ) 
'   '  `-'   `-'  
                  """
print(bcolors.BANNER + banner)
assignIpAndDomain()
module = input(bcolors.MAIN + "1 - OSINT\n")

if module == "1":
    OSINT()