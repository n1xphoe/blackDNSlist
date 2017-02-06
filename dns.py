import os.path
import re
import urllib.request

# Location of the DNS File
# You'll want to customize this.
scriptpath = os.path.dirname(r"\\myserver\location\dnslogs\ ")
# DNS file name
dnsFile = os.path.join(scriptpath, 'dns.log')
# Location of black list database
blackListUrl = urllib.request.urlopen('http://mirror1.malwaredomains.com/files/justdomains')

# Declare lists to be used
blackList = []
dnsList = []

# Create a list of lists from the Microsoft DNS file.
with open(dnsFile,'r') as myDnsFile:
    for dnsLine in myDnsFile:
        # Only use lines that have Snd to reduce the size of the search.
        if re.findall(r'Snd',dnsLine) == ['Snd']:
            # Use regex to parse everything between the parentheses
            dnsSub = re.findall(r'\)(.+?)\(',dnsLine)
            # Join each using a period to var dnsUrl
            dnsUrl = '.'.join(dnsSub)
            # Use regex to find the IP address
            ipSub = re.findall(r'\d+\.\d+\.\d+\.\d+',dnsLine)
            ipRequest = '.'.join(ipSub)
            # Use regex to find the date
            dateSub = re.findall(r'\d+\/\d+\/\d+',dnsLine)
            date = '/'.join(dateSub)
            # Use regex to find the time
            timeSub = re.findall(r'\d+\:\d+\:\d+ .[M]',dnsLine)
            time = ':'.join(timeSub)
            # Add to list
            dnsList.append([dnsUrl,ipRequest,date,time])

# Create a list from the black list file.
blackList = blackListUrl.read().decode('utf-8').splitlines()

# Compare both lists
for eachDnsList in dnsList:
    for eachBlackList in blackList:
        if eachBlackList == eachDnsList[0]:
            print("Match", eachDnsList[0], " was accessed by ", eachDnsList[1], " on ", eachDnsList[2], eachDnsList[3])
