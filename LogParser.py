import re
import pygeoip

def ipGeoLocate(ip):	# function for mapping Unique IP Addresses to countries
	GeoIPDatabase = 'C:\\Users\\aldabaa\\Desktop\\Horangi\\GeoIP.dat'
	country = ""
	ipData = pygeoip.GeoIP(GeoIPDatabase)
	print "Geo locating IP:"+ip
	if(not ip and "@" not in ip):
		country = ipData.country_name_by_addr(ip)
	return country

def indexByIP(ip,log): # function that returns the corresponding log entries found per unique IP address
	listIndex = []
	for x,line in enumerate(log, start=0):
		if ip in line:
			listIndex.append(x)
	return listIndex


def populateLogDictionary(uniqueIPs,log):	# function for building dictionary of IP address : hit line from log file
	logDictionary = {}
	for IP in uniqueIPs:
		print "Indexing IP:"+IP
		logDictionary[IP] = indexByIP(IP,log) #	assign per IP its list of hits per log file entry
	return logDictionary

def detectSQLI(url):	#function for detecting the presence of SQL Injection per log entry file
	escapeCharRegex = re.compile("('[^s])|(\"[^s])")
	if escapeCharRegex.search(url): #check for presence of escape literals
		return 1
	else:
		return 0
def detectRFI(url):		#function for detecting the presence of remote file inclusion per log entry
	remoteInclusionRegex = re.compile("(ft|htt)ps?.*\?+")
	if remoteInclusionRegex.search(url):
		return 1
	else:
		return 0

def detectWebShell(url):	#function for detecting the presence of web shells per log entry
	webShellRegex = re.compile("http://\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}")
	if webShellRegex.search(url):
		return 1
	else:
		return 0

logDictionary = {} # dictionary containing unique IPs and corresponding hit lines in log file
IPList = [] # list of IP addresses
logList = []
logLine = []
webShellPattern = re.compile("")
fileInclusionPattern = re.compile("")
dateRegex = re.compile("2015-\d\d-\d\d")
ipFile = open("C:\\Users\\aldabaa\\Desktop\\Horangi\\uniqueIP.txt","w") # write to IP log file of unqiue IP addresses
countryFile = open("C:\\Users\\aldabaa\\Desktop\\Horangi\\countryList.txt","w")
sqliFile = open("C:\\Users\\aldabaa\\Desktop\\Horangi\\sqli.txt","w")
webShellFile = open("C:\\users\\aldabaa\\Desktop\\Horangi\\webshells.txt","w")
remoteFileInclusionFile = open("C:\\users\\aldabaa\\Desktop\\Horangi\\remotefileinclusion.txt","w")

print "building log list"
with open("C:\\Users\\aldabaa\\Desktop\\Horangi\\CTF1.log","r") as lines: #take log strings and place into a list to remove multi-line logs in logfile
	for line in lines: # iterate through list of all events from log file
		if line[0] != "#":
	 		splitLine = line.split(" ") #split the line by white space to parse date of log entry
	 		if dateRegex.search(splitLine[0]): #check if current line contains the log date. If it contains the date then add to the log list
	 			if not logLine: #add the very first log entry in log file
	 				logLine.append(line)
	 			logList.append(''.join(logLine)) #join the multi-line log strings into one string and add to the log list
	 			logLine = []	#flush log line list
			logLine.append(line)

print "building unique IP list"

for line in logList: # iterate through list of all logs from log list to parse requesting IP
	if line[0] != "#":
		initialSplit = re.split("\s*-*\s(80|443)\s(-|(.*@.*\.\w)\s)",line) # split each line in log file per - 80/443 - regex
		if "@" in initialSplit[2]:
			finalSplit = re.split(" ",initialSplit[2])[1]
		if initialSplit[4] and "@" not in initialSplit[2]:
			finalSplit = re.split(" ",initialSplit[4])[0] # split the line further by white space to extract IP address
		IPList.append(finalSplit)

print "building IP index"
uniqueIPs = set(IPList)

logDictionary = populateLogDictionary(uniqueIPs,logList)


print "writing unique IP's to file"
for IP in uniqueIPs:
	ipFile.write(IP+'\n')
ipFile.close()

print "building Number of hits and country per IP"
#1.2 list of unique IP's with country and number of hits per IP
for ip in uniqueIPs:
	countryFile.write('IP Address: '+ip+'\nCountry: '+ipGeoLocate(ip)+'\nHit Count:'+str(len(logDictionary[ip]))+'\n')
	
countryFile.close()

print "building list of activities per IP"
#1.3 list of all activity per IP in text files
for ip in uniqueIPs:
	ipActivityFile = open("C:\\Users\\aldabaa\\Desktop\\Horangi\\IPactivity\\"+ip+'.txt',"w")
	ipActivityFile.write(ip+'\nActivity:\n')
	for activity in logDictionary[ip]:
		ipActivityFile.write(logList[activity])
		
ipActivityFile.close()

print "detecting attacks in log"
for line in logList:
	initialSplit = re.split("\s(GET|POST|OPTIONS|HEAD|ASDF|TRACE|TRACK)\s",line)
	finalSplit = re.split("\s*-* (80|443) (-|(.*@.*\.com ))",initialSplit[2])
	if detectSQLI(finalSplit[0]) == 1:
		sqliFile.write(line+'\n')
	if detectRFI(finalSplit[0]) == 1:
		remoteFileInclusionFile.write(line+'\n')
	if detectWebShell(finalSplit[0]) == 1:
		webShellFile.write(line+'\n')

webShellFile.close()
remoteFileInclusionFile.close()
sqliFile.close()

