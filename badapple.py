#!/usr/bin/python
import time
import os
import subprocess
import subprocess as sp
import grp
import getpass

def main():

	try:

		banner()

		username=getpass.getuser()
		pwd=os.popen('pwd').read()
		print('\x1b[6;1;32m' + '[*] Prepairing Directories . . .' +'\x1b[0m')

		pwdCmd = (pwd)
		command = (username,pwd)
		
		# Initialize browser artifact directories
		initSafariDir = ("mkdir SafariArtifacts /Users/%s %s")
		initChromeDir = ("mkdir ChromeArtifacts /Users/%s %s")
		initFireFoxDir = ("mkdir FireFoxArtifacts /Users/%s %s")
		initMasterDir = ("mkdir mac_forensicdata /Users/%s %s")
	
		# Creating browser artifact directories
		os.system(initSafariDir % command)
		os.system(initChromeDir % command)
		os.system(initFireFoxDir % command)
		os.system(initMasterDir % command)

		print('\n')
		time.sleep(2)

		# Call Functions

		getOSInfo()
		getUserGroups()
		getServiceInfo()
		getSpecialFiles()
		getNetworkInfo()
		getSafariArtifacts() 
		getChromeArtifacts()
		getFireFoxArtifacts()
		

		print('\x1b[6;1;32m' + '\n[*] File Acquisition completed - Zipped as \'mac_artifacts.zip\'. ' +'\x1b[0m')
		print('\x1b[6;1;32m' + '[*] Reports will be located in system path where script is running.\n ' +'\x1b[0m')

	except NameError:
		print('\x1b[6;1;31m' + '[*] Problem Accessing Global Variable' +'\x1b[0m')

# Performs commands to query OS and hardware information
def getOSInfo():
	commands=('uname -a', 'uname -r', 'uname -n', 'uname -m', 'hostname', 'uname -mrs', 'df -a')
	with open('OSInfo.txt','w') as filename1:
		filename1.write("[+] OS Info\n")
		print('\x1b[6;1;32m' + '[+] Acquiring OS, Kernel and Device Info . . .' +'\x1b[0m')
		time.sleep(2)
		for command in commands:
			print('[+] Running Task: {}'.format(command))
			time.sleep(.10)
			filename1.write('[+] Task: {}'.format(command) +'\n')
			filename1.write(os.popen(command).read()+'\n')
	filename1.close()
	print('[+] Completed - Saved as OSInfo.txt')

# Performs commands to query information about users and groups 
def getUserGroups():
	commands=('cat /etc/group', 'id', 'who', 'last')
	with open('UsersandGroups.txt','w') as filename4:
		filename4.write('[+] User and Group Info\n')
		print('\x1b[6;1;32m' + '\n[+] Acquiring Users and Groups Info . . .' +'\x1b[0m')
		time.sleep(2)
		for command in commands:
			print('[+] Running Task: {}'.format(command))
			time.sleep(.10)
			filename4.write('[+] Task: {}'.format(command) +'\n')
			filename4.write(os.popen(command).read()+'\n\n')
	print('[+] Completed - Saved as UsersandGroups.txt')
	filename4.close()

# Performs commands to query process and service information
def getServiceInfo():
	commands=('ps aux', 'ps -ef', 'ls -alh /usr/bin/', 'ls -alh /sbin/')
	rootCommands=('ps aux | grep root', 'ps -ef | grep root')
	print('\x1b[6;1;32m' + '\n[+] Acquiring Service Info . . . ' +'\x1b[0m')
	with open('serviceInfo.txt','w') as filename2:
		filename2.write("[+] System and Services Info \n\n")
		for command in commands:
			print('[+] Running Task: {}'.format(command))
			time.sleep(.10)
			filename2.write(os.popen(command).read()+'\n\n\n')
		filename2.write("[+] Commands Spawned by Root\n\n")
		for cmds in rootCommands:
			print('[+] Running Task: {}'.format(cmds))
			time.sleep(.10)
			filename2.write(os.popen(cmds).read()+'\n\n')
		filename2.write("[+] Login Events\n\n")
		filename2.write(os.popen("ps aux | grep login").read()+'\n\n')
		filename2.write("[+] Startup Items\n\n")
		filename2.write(os.popen("ls /Library/StartupItems/").read()+'\n\n')
		print('[+] Completed - Saved as serviceInfo.txt')
	filename2.close()
	time.sleep(2)

# Acquires files of interest, such as bash history
def getSpecialFiles():
	commands=('cat ~/.bash_history', 'cat ~/.bash_history', 'ls -la /', 'ls -la ~/.ssh/')
	print('\x1b[6;1;32m' + '\n[+] Acquiring Files of Interest . . .' +'\x1b[0m')
	time.sleep(.10)

	with open ('specialFiles.txt','w') as filename5:
		for command in commands:
			print('[+] Running Task: {}:'.format(command))
			time.sleep(.10)
			filename5.write('[+] Task: {} \n'.format(command))
			filename5.write(os.popen(command).read()+'\n')
	print('[+] Completed - Saved as specialFiles.txt')
	filename5.close()

# Performs commands to gather network information
def getNetworkInfo():
	commands=('ifconfig','lsof -i', 'grep 80 /etc/services', 'lsof -iTCP -sTCP:LISTEN -n -P','netstat -anv | grep [.]PORT')
	with open('networkInfo.txt','w') as filename3:
		print('\x1b[6;1;32m' + '\n[+] Acquiring Network Info . . .' +'\x1b[0m')
		for command in commands:
			print('[+] Running Task: {}'.format(command))
			time.sleep(.10)
			filename3.write('[+] Running Task: {}'.format(command))
			filename3.write(os.popen(command).read() +'\n')
	print('[+] Completed - Saved as networkInfo.txt')
	time.sleep(2)
	filename3.close()

# Acquire Safari browser artifacts
def getSafariArtifacts():
	print('\x1b[6;1;32m' + '\n[*] Retrieving Safari Artifacts' +'\x1b[0m')
	username=getpass.getuser()
	pwd=os.popen('pwd').read()
	command = (username,pwd)
	safariDownloads = ("cp /Users/%s/Library/Safari/Downloads.plist %s")
	safariHistory=("cp /Users/%s/Library/Safari/History.db %s")
	safariLastSession=("cp /Users/%s/Library/Safari/LastSession.plist %s")
	safariRecentlyClosedTabs=("cp /Users/%s/Library/Safari/RecentlyClosedTabs.plist %s")
	safariSearchDescriptions=("cp /Users/%s/Library/Safari/SearchDescriptions.plist %s")
	safariTopSites=("cp /Users/%s/Library/Safari/TopSites.plist %s")

	commands=(safariDownloads, safariHistory, safariLastSession, safariRecentlyClosedTabs, safariSearchDescriptions, safariTopSites)
	for x in commands:
		time.sleep(.5)
		os.system(x % command)

	mvFiles=('mv Downloads.plist History.db LastSession.plist RecentlyClosedTabs.plist SearchDescriptions.plist TopSites.plist SafariArtifacts/')
	os.system(mvFiles)

# Acquire Chrome browser artifacts
def getChromeArtifacts():
	print('\x1b[6;1;32m' + '[*] Retrieving Google Chrome Artifacts' +'\x1b[0m')
	username=getpass.getuser()
	pwd=os.popen('pwd').read()
	command = (username,pwd)
	chromeCookies = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Cookies %s")
	chromeCurrentSession = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Current\ Session %s")
	chromeCurrentTabs = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Current\ Tabs %s")
	chromeHistory = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/History %s")
	chromeTopSites = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Top\ Sites %s")
	chromeLastSession = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Last\ Session %s")
	chromeLastTabs = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Last\ Tabs %s")
	chromeLastSession = ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Last\ Session %s")
	chromeWebData= ("cp /Users/%s/Library/Application\ Support/Google/Chrome/Default/Web\ Data %s")

	# Iterating through system commands
	commands=(chromeCookies, chromeCurrentSession, chromeCurrentTabs, chromeHistory, chromeTopSites, chromeLastSession, chromeLastTabs, chromeLastSession, chromeWebData)
	for x in commands:
		os.system(x % command)
	presentcmd=(pwd)
	mvFiles=('mv Cookies Current\ Session Current\ Tabs History Top\ Sites Last\ Tabs Last\ Session Web\ Data ChromeArtifacts/')
	os.system(mvFiles)

# Acquire FireFox browser artifacts
def getFireFoxArtifacts():
	print('\x1b[6;1;32m' + '[*] Retrieving FireFox Artifacts' +'\x1b[0m')

	path=("/Users/defalt/Library/Application Support/Firefox/Profiles/")
	folder = [x for x in os.listdir(path) if os.path.isdir(os.path.join(path,x))]
	newPath=(''.join(folder))
	
	username=getpass.getuser()
	pwd=os.popen('pwd').read()
	command = (username,newPath,pwd)

	FireFoxCookies = ("cp /Users/%s/Library/Application\ Support/Firefox/Profiles/%s/cookies.sqlite %s")
	FireFoxFormHistory = ("cp /Users/%s/Library/Application\ Support/Firefox/Profiles/%s/formhistory.sqlite %s")
	FireFoxLogins = ("cp /Users/%s/Library/Application\ Support/Firefox/Profiles/%s/logins.json %s")
	FireFoxPlaces = ("cp /Users/%s/Library/Application\ Support/Firefox/Profiles/%s/places.sqlite %s")

	commands=(FireFoxCookies, FireFoxFormHistory, FireFoxLogins, FireFoxPlaces)
	for x in commands:
		time.sleep(.5)
		os.system(x % command)
		
	mvFiles=('mv cookies.sqlite formhistory.sqlite logins.json places.sqlite FireFoxArtifacts/')
	os.system(mvFiles)

# Will zip the data for export
'''
def zipData():
	print('\x1b[6;1;32m' + '\n[+] Preparing file for export. . .' +'\x1b[0m')
	time.sleep(2)
	os.system("mv ChromeArtifacts/ mac_forensicdata; mv SafariArtifacts/ mac_forensicdata; mv FireFoxArtifacts/ mac_forensicdata")
	os.system("mv *.txt mac_forensicdata/")
	os.system("zip -r mac_artifacts mac_forensicdata/; rm -r mac_forensicdata")
	time.sleep(1)
	print('\x1b[6;1;32m' + '\n[+] Export Complete. . .' +'\x1b[0m')
'''

def banner():
	
	print("MMMMMMMMMMMMMMMMMx  ^  xMMMMMMMMMMMMMMMM")
	print("MMMMMMMMMMWN0Oxdo  | |  MxO0XWMMMMMMMMMM")
	print("MMMMMMMMWNOo;..    | |   ..;oONWMMMMMMMM")
	print("MMMMMMWKo'         | |       'o0WMMMMMMM")
	print("MMMMMKl.           | .;o;       .lKMMMMM")
	print("MMMWk'             'lkN0,         'kWMMM")
	print("MMWk.         ....:xxo:'.          .kWMM")
	print("MM0'       .:x0XX0kxxk0XXXOoo.      '0MM")
	print("MNl       .dWMMMMMMMMMMMMMXo.        lNM")
	print("MK;____   cNMMMMMMMMMMMMMWo    _____ ;KM")
	print("MK,--- >> lWMMMMMMMMMMMMMM  << -----,KMM")
	print("MX:--     ;KMMMMMMMMMMMMMKc.     --- :XM")
	print("MWx.        NMMMMMMMMMMMMMMd.       .xWM")
	print("MMXc         MMMMMMMMMMMMMM.        cXMM")
	print("MMMNd.        ;MMMM| |MMMM.'.     .dNMMM")
	print("MMMW0l.            | |          .l0WMMMM")
	print("MMMMMMWK:.         | |        . :dKWMMMM")
	print("MMMMMMMkd:.        | |	    .:dKWMMMMMMM")
	print("MMMMMMMMMMWXkoc;,.. v .,;cdkXWMMMMMMMMMM")
	print("MMMMMMMMMMMMMMMWNXK V XNWMMMMMMMMMMMMMMM")
	print("\n")
	print('\x1b[6;1;32m' + '[*] Running Mac Enumeration & Forensic Artifact Acquisition\n' +'\x1b[0m')
	print('\x1b[6;1;32m' + '~ endeav0r\n' +'\x1b[0m')
	time.sleep(3)

if __name__ == "__main__": 
  
    # calling main function 
    main() 

