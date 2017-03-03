#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import json
import re
from datetime import datetime
from sys import platform

HOME = os.environ['HOME'] 	                   # path to home directory
LOG_PATH = "/var/log/auth.log"                 # Path to the log file to scan
APP_FILES_PATH = HOME + "/.a3_secure_log"      # All application files will be stored in this directory
FAILED_PATH = APP_FILES_PATH + "/blocked.json" # Stores information about failed password attempts

DATE_FMT = "%b %d %H:%M:%S"                    # Fedora 24 sshd date format; not sure about Ubuntu or Fedora 25

failed_info = {}   # A dictionary of dictionaries of the form {[ip address string]: {"attempt_count": [number of attempts], "last_attempt":[timestamp]}, [ip address string]...}
block_threshold = 0

def execute(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line 
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)

def record_operations(date, ip):
    epoch_time = int(date.timestamp())
    if ip in failed_info:
        if failed_info[ip]["last_attempt"] < epoch_time:
            failed_info[ip]["last_attempt"] = epoch_time
            failed_info[ip]["attempt_count"] += 1
    else:
        failed_info[ip] = {"last_attempt":epoch_time, "attempt_count":1}

def scan_var_log():
    # Fedora /var/log/secure format: Feb 23 21:32:05 localhost sshd[5755]: Failed password for shane from 192.168.1.67 port 51295 ssh2
    # Ubuntu /var/log/auth.log format?

    try:
        ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') # Not perfect, but it'll do for our purposes
        for line in execute(["tail", "-f", LOG_PATH]):
            index = line.find('Failed password for')
            if index != -1:
                # This is a complete hack, but strptime doesn't allow converting just part of a string.
                # Basically, this tries to convert a string that WILL fail and raise an exception so that
                # we can cut out the unconverted data.
                #
                # The docs for the C implementation of strptime, which this wraps, state that "The return
                # value of the function is a pointer to the first character not processed in this function
                # call." I.e., it is NOT an error in the C function to pass a string with characters after
                # the date. Why it's an error in the Python implementation, and why there's no alternative
                # API with the correct behaviour (or more accurately, why the one that fails on unconverted
                # input itself isn't the alternative API), is beyond me.
                try:
                    date = datetime.strptime(line, DATE_FMT)
                except ValueError as v:
                    unconverted_msg = "unconverted data remains: "
                    exception_msg = str(v)
                    start = exception_msg.find(unconverted_msg)
                    if start != -1:
                        date_end = len(line) - (len(exception_msg) - len(unconverted_msg))
                        date = datetime.strptime(line[:date_end], DATE_FMT)
                        date = date.replace(year=2017) # Oh well
                    else:
                        raise v

                ip = ip_pattern.search(line).group(0)
                message = line.split(' ')
                record_operations(date, ip)

                print("Failed attempt number " + str(failed_info[ip]["attempt_count"]) + " for IP " + ip)

                # Block traffic from this machine
                if failed_info[ip]["attempt_count"] == block_threshold:
                    print("Blocking ssh traffic from " + ip)
                    os.system("iptables -A INPUT -s " + ip + " -j DROP")

    except KeyboardInterrupt:
        print("\nCaught KeyboardInterrupt; exiting")
        with open(FAILED_PATH, 'w') as f:
            json.dump(failed_info, f)
            f.flush()

def main():
    scan_var_log()
    sys.exit()

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("usage: " + sys.argv[0] + " [block threshold]")

    block_threshold = int(sys.argv[1])

    if not os.path.exists(APP_FILES_PATH):
        os.mkdir(APP_FILES_PATH)
    else:
        # load the info if there is any
        if os.path.exists(FAILED_PATH) and os.stat(FAILED_PATH).st_size > 0:
            with open(FAILED_PATH, 'r') as f:
                failed_info = json.load(f)

    distro = None

    # Try to figure out the distro from /etc/os-release
    if os.path.exists("/etc/os-release"):
        os_release_file = open("/etc/os-release", "r")
        for line in iter(os_release_file):
            words = line.split("=")
            key, value = words[0], words[1]

            if key == "NAME":
                distro = value
                distro_lower = distro.lower()
                if "ubuntu" in distro_lower:
                    LOG_PATH = "/var/log/auth.log"
                    DATE_FMT = None
                    break
                elif "fedora" in distro_lower:
                    LOG_PATH = "/var/log/secure"
                    DATE_FMT = "%b %d %H:%M:%S"
                    break

        os_release_file.close()

    if distro:
        print("Distro: " + distro)
        main()
