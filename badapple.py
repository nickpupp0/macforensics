#!/usr/bin/python
import time
import os
import subprocess
import subprocess as sp
import grp
import getpass
from os import listdir

def main():

	try:
		
		banner()

		# Call Functions
		getOSInfo()
		getUserGroups()
		getServiceInfo()
		getSpecialFiles()
		getFSEvents()
		getNetworkInfo()
		getBrowserArtifacts()
		getSysPreferences()
		zipData()
	
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
	os.system('mkdir OSInfo; mv OSInfo.txt OSInfo/')
	filename1.close()
	print('[+] Completed - Saved as OSInfo.txt')

# Perform
def getSysPreferences():
	print('\x1b[6;1;32m' + '\n[*] Acquiring System Preference Logs' +'\x1b[0m')
	time.sleep(1)
	username=getpass.getuser()
	pwd=os.popen('pwd').read()
	os.system('mkdir System_Preferences >/dev/null 2>&1; cp /Library/Preferences/*.plist /Users/%s/Desktop/mac_forensics/System_Preferences/ >/dev/null 2>&1' % (username))

# Performs commands to query information about users and groups 
def getUserGroups():
	commands=('cat /etc/group', 'id', 'who', 'last','dscacheutil -q group')
	with open('UsersandGroups.txt','w') as filename4:
		filename4.write('[+] User and Group Info\n')
		print('\x1b[6;1;32m' + '\n[+] Acquiring Users and Groups Info . . .' +'\x1b[0m')
		time.sleep(2)
		for command in commands:
			print('[+] Running Task: {}'.format(command))
			time.sleep(.10)
			filename4.write('[+] Task: {}'.format(command) +'\n')
			filename4.write(os.popen(command).read()+'\n\n')
	os.system('mkdir UserGroups; mv UsersandGroups.txt UserGroups/')
	print('[+] Completed - Saved as UsersandGroups.txt')
	filename4.close()

# Performs commands to query process and service information
def getServiceInfo():
	commands=('ps','ps aux', 'ps -ef', 'ls -alh /usr/bin/', 'ls -alh /sbin/', 'ls /Applications')
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
	os.system('mkdir serviceInfo; mv serviceInfo.txt serviceInfo/')
	filename2.close()
	time.sleep(2)

def getFSEvents():
	print('\x1b[6;1;32m' + '\n[*] Acquiring FSEvent Logs. . .' +'\x1b[0m')
	time.sleep(1)
	username=getpass.getuser()
	pwd=os.popen('pwd').read()
	os.system('mkdir fsevents >/dev/null 2>&1; cp -r /.fseventsd/* /Users/%s/Desktop/mac_forensics/fsevents/' % (username))
	print('\x1b[6;1;32m' + '[+] Completed. . .' +'\x1b[0m')

# Acquires files of interest, such as bash history
def getSpecialFiles():
	commands=('history', 'ls -la /', 'cat /var/db/dslocal/nodes/Default/users/*', 'cat /Library/Receipts/InstallHistory.plist','ls ~/.Trash/' )
	print('\x1b[6;1;32m' + '\n[+] Acquiring Files of Interest . . .' +'\x1b[0m')
	time.sleep(.10)

	with open ('specialFiles.txt','w') as filename5:
		for command in commands:
			print('[+] Running Task: {}:'.format(command))
			time.sleep(.10)
			filename5.write('[+] Task: {} \n'.format(command))
			filename5.write(os.popen(command).read()+'\n')
	os.system('mkdir specialFiles; mv specialFiles.txt specialFiles/')
	print('[+] Completed - Saved as specialFiles.txt')
	filename5.close()

# Performs commands to gather network information
def getNetworkInfo():
	commands=('ifconfig','lsof -i', 'lsof -PiTCP -sTCP:LISTEN', 'scutil --dns','cat /etc/resolv.conf','grep 80 /etc/services', 'lsof -iTCP -sTCP:LISTEN -n -P','netstat -anv | grep [.]PORT', 'cat /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist')
	with open('networkInfo.txt','w') as filename3:
		print('\x1b[6;1;32m' + '\n[+] Acquiring Network Info . . .' +'\x1b[0m')
		for command in commands:
			print('[+] Running Task: {} \n'.format(command))
			time.sleep(.10)
			filename3.write('[+] Running Task: {}'.format(command))
			filename3.write(os.popen(command).read() +'\n')
	os.system('mkdir networkInfo; mv networkInfo.txt networkInfo/')
	print('[+] Completed - Saved as networkInfo.txt')
	time.sleep(2)
	filename3.close()

# Acquire Browser Artifacts per user in /User
def getBrowserArtifacts():
	print('\x1b[6;1;32m' + '\n[*] Retrieving Browser Artifacts' +'\x1b[0m')
	time.sleep(1)

	path=("/Users/")
	pwd=os.popen('pwd').read()
	users=[]
	os.system('mkdir Browser_Artifacts')

	# Iterating through users in /Users/
	print('\x1b[6;1;32m' + '[*] Retrieving Users . .' +'\x1b[0m')
	userDir = [x for x in os.listdir(path) if os.path.isdir(os.path.join(path,x))]
	time.sleep(2)

	# Adding users in /Users/ to array
	for x in userDir:
		users.append(x)

	# Generate user directories and putting them in pwd
	print('\x1b[6;1;32m' + '[*] Creating User Directories . . .' +'\x1b[0m\n')
	time.sleep(2)
	for x in users:
		username = x
		pwd=os.popen('pwd').read()
		print('Adding {}'.format(username))
		#os.system('cp /Users/%s/Library/Safari/Downloads.plist' % (username))
		print('Retrieving Artifacts for User: {}'.format(x))
		time.sleep(1)

		# Retrieve Safari Data
		try:
			os.system('cd Browser_Artifacts/; mkdir %s >/dev/null 2>&1; cd %s; mkdir safariArtifacts >/dev/null 2>&1; cp -r /Users/%s/Library/Safari/* safariArtifacts/ >/dev/null 2>&1' % (username, username, username))
	
		except OSError:
			print('\x1b[6;1;31m' + '[*] No Safari Data for User: {}'.format(x) +'\x1b[0m')
		time.sleep(1)

		# Retrieve Google Chrome Data
	
		os.system('cd Browser_Artifacts/; mkdir %s >/dev/null 2>&1; cd %s; mkdir chromeArtifacts >/dev/null 2>&1; cp -r /Users/%s/Library/Application\ Support/Google/Chrome/Default/* chromeArtifacts/ >/dev/null 2>&1' % (username, username, username))
		
		try:
			#print('getting firefox data')
			time.sleep(1)
			path=("/Users/%s/Library/Application Support/Firefox/Profiles/" %(x))
			folder = [x for x in os.listdir(path) if os.path.isdir(os.path.join(path,x))]
			profile=(''.join(folder))
			os.system('cd Browser_Artifacts/; mkdir %s >/dev/null 2>&1; cd %s; mkdir FireFoxArtifacts >/dev/null 2>&1; cp -r /Users/%s/Library/Application\ Support/Firefox/Profiles/%s* FireFoxArtifacts/ >/dev/null 2>&1' % (username, username, username, profile))

		except OSError:
			print('\x1b[6;1;31m' + '[*] No Firefox Data for User: {}'.format(x) +'\x1b[0m')

	print('\x1b[6;1;32m' + '\n[*] Completed.' +'\x1b[0m')

# Will zip the data for export
def zipData():
	print('\x1b[6;1;32m' + '\n[+] Preparing file for export. . .' +'\x1b[0m')
	os.system('mkdir mac_artifacts')
	os.system("mv OSInfo/ mac_artifacts/; mv UserGroups/ mac_artifacts/; mv networkInfo/ mac_artifacts/; mv serviceInfo/ mac_artifacts/; mv specialFiles/ mac_artifacts/; mv Browser_Artifacts/ mac_artifacts; mv System_Preferences/ mac_artifacts/; mv fsevents/ mac_artifacts")
	os.system("zip -r mac_artifacts mac_artifacts/ >/dev/null 2>&1; rm -r mac_artifacts; cp mac_artifacts.zip ~")
	print('\x1b[6;1;32m' + '\n[+] Export Completed Successfully.' +'\x1b[0m')

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
	print("    __           __               __")   
  	print("   / /  ___ ____/ /__ ____  ___  / /___ ") 
 	print("  / _ \/ _ `/ _  / _ `/ _ \/ _ \/ / -_/ ")
	print(" /_.__/\_,_/\_,_/\_,_/ .__/ .__/_/\__/ ")
	print("                    /_/  /_/           ")
	print("Created by: Nick Puppo")
	print("Lets Connect: https://www.linkedin.com/in/nicholas-puppo-99853993/ | https://github.com/ceaba55555")
	time.sleep(3)
	print("\n")
	print('\x1b[6;1;32m' + '[*] Running MacOS Enumeration & Forensic Artifact Acquisition\n' +'\x1b[0m')
	time.sleep(3)

if __name__ == "__main__": 
  
    # calling main function 
    main() 







