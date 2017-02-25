
import os
import subprocess
import sys
import time
from sys import platform

MOD_TIME = 0				# Keep track of last modification of the /var/log/secure file
HOME = os.environ['HOME'] 	# path to home directory
PATH = "/var/log/auth.log"

def insert_into_file(data):
    exit()

def record_operations(date, msg):
    time_of_attempt = msg[0].split('T')[1].split(':')
    time_of_attempt[2] = int(float(time_of_attempt[2].split('+')[0]))

    year, month, day = date[0], date[1], date[2]
    hour, minute, second = time_of_attempt[0], time_of_attempt[1],\
                           time_of_attempt[2]
    user, ip = msg[6], msg[8]
    data = {"year" : int(year), "month" : int(month), "day" : int(day), "ip" :
            ip, "user" : user, "hour" : int(hour), "minute" : int(minute),
            "second" : int(second)}
    insert_into_file(data)

def check_for_failed_password(list_of_read_lines):
    l = list_of_read_lines
    for i in range(len(l)):
        if ' '.join(l[i].split(' ')[3:6]) == 'Failed password for':
            x = l[i].split('T')  
            date = x[0].split('-')
            message = l[i].split(' ')
            record_operations(date, message)
        else:
            continue

def scan_var_log():
    global MOD_TIME
    new_MOD_TIME = os.path.getmtime(PATH)
    if MOD_TIME == new_MOD_TIME:
        return
    else:
        list_of_read_lines = []
        try:
            with open(PATH) as f:
                list_of_read_lines = f.readlines()
                check_for_failed_password(list_of_read_lines)
        except IOError as e:
            print("You do not have enough permissions to access the file.\n") 
            sys.exit(1)

        MOD_TIME = new_MOD_TIME

def main():
    scan_var_log()
    sys.exit()

if __name__ == "__main__":
    print(platform)
    if (platform == "linux"):
        if os.path.exists("/var/log/secure"):
            PATH = "/var/log/secure"
            sys.exit(main())
        else:
            print('/var/log/secure does not exist. Make sure the file exists and try again later.')
            sys.exit(1)
    else:
        if os.path.exists("/var/log/auth.log"):
            PATH = "/var/log/auth.log"
            sys.exit(main())
        else:
            print('/var/log/auth.log does not exist. Make sure the file exists and try again later.')
            sys.exit(1)