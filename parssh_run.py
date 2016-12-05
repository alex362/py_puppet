# Author: Aleksandar Stoykovski <bavarien362@protonmail.com>

# Description
# Run ssh commands in parallel on multiple hosts
# Read as standard input from puppet_hosts file or using option -f to manually give a file
# The format should be: "ssh_portnumber hostname"

# paramiko is not part from the default python modules, it needs to be installed.

import argparse
import logging
import time
import getpass
import datetime
import threading
import os
import re
import paramiko
import Queue

# create object parser. help(argparse) 
parser = argparse.ArgumentParser()
parser.add_argument('-f', action="store", dest="file_path", required=False, help="Speficy path to hosts file")
parser.add_argument('-l', action="store_true", dest="list_only", required=False, help="list all host from host file")

parser.add_argument('-t', action="store", dest="connect_timeout", required=False, help="ssh timeout to hosts in seconds")
parser.add_argument('-T', action="store", dest="threads", required=False, help="# of threads to run")
parser.add_argument('-u', action="store", dest="user", required=False, help="Specify username (by default is the one used for login)")
parser.add_argument('-c', action="store", dest="command_string", required=False, help="Command to run")
parser.add_argument('-r', action="store", dest="host_match", required=False, help="Select Hosts matching supplied pattern")
parser.add_argument('-s', action="store_true", dest="sudo", required=False, help="Run command using sudo")

args = parser.parse_args()

logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

# returns current time in epoch
stime = time.time()


connect_timeout = 5
if args.connect_timeout:
    connect_timeout = args.connect_timeout

workers = 20
if args.threads:
    workers = int(args.threads)

user = getpass.getuser()

# print user
if args.user:
    user = args.user

successful_logins = []
failed_logins = []

timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")

logfile_dir = "/tmp/"
logfile_path = '%sssh_run.%s' % (logfile_dir, timestamp)
logfile = open(logfile_path, 'w')

def get_hosts(file_path):
    if os.path.exists(file_path):
        hosts = open(file_path)
        selected_hosts = []
        # print args.host_match
        if not args.host_match:
            selected_hosts = list(hosts)
            log_and_print("[INFO]: SELECTING ALL HOSTS")
        else:
            host_match = args.host_match
            for host in hosts:
                for match in host_match.split():
                    if re.search(match, host):
                        selected_hosts.append(host)
            log_and_print("[INFO]: MATCHING HOSTNAMES WITH '%s'" % (host_match))
    else:
        log_and_print("[ERROR]: % s does not exist ! " % (file_path))
        exit(1)

    return selected_hosts


def log_and_print(message):
    print message
    if not args.list_only:
        logfile.write(message + '\n')


def ssh_to_host(hosts):
    for i in range(workers):
        t = threading.Thread(target=worker, args=(user,))
        t.daemon = True
        t.start()

    for hostname in hosts:
        hostname = hostname.rstrip()
        q.put(hostname)

    q.join()

def worker(user):
    # print user
    while True:
        hostname = q.get()
        # print hostname + "hoztname"
        node_shell(hostname, user)
        q.task_done()

def node_shell(hostname, user):
        portnr,hostname = hostname.split()
        # print portnr, hostname
        port=int(portnr)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(hostname, username=user, timeout=connect_timeout, port=port)
            transport = ssh.get_transport()
            transport.set_keepalive(1)

            cmd = args.command_string
            # print cmd
            # print args.sudo
            if args.sudo:
                try:
                # have to use invoke shell for sudo due to ssh config on machines requiring a TTY
                    # print "worsk"
                    channel = ssh.invoke_shell()
                    sudocmd = 'sudo ' + cmd

                    channel.send(sudocmd + '\n')

                    buff = ''
                    while not buff.endswith('$ '):
                        resp = channel.recv(9999)
                        buff += resp
                    for line in buff.split('\n'):
                        if cmd not in line and not line.endswith('$ ') or not line.endswith('*'):
                            log_and_print("%s: %s" % (hostname, line))

                    successful_logins.append(hostname)
                    ssh.close()
         
                except Exception as e:
                    log_and_print("ERROR: Sudo failed: %s" % (e))  
          
            else:
                (stdin, stdout, stderr) = ssh.exec_command(cmd)

            ## stdout 
                for line in stdout.readlines():
                        # print "ok"
                        line = line.rstrip()
                        log_and_print("%s: %s" % (hostname, line))
            ## stderr
                for line in stderr.readlines():
                        print "nok"
                        line = line.rstrip()
                        log_and_print("%s: %s" % (hostname, line))
         
                successful_logins.append(hostname)
                ssh.close()

        except Exception as e:
            log_and_print("%s: failed to login : %s" % (hostname, e))
            failed_logins.append(hostname)
            ssh.close()



if __name__ == "__main__":
    file_path = "/tmp/puppet_hosts"

    if args.file_path:
        file_path = args.file_path
        if '~' in file_path:
            print "[ERROR]: -f does not supported '~'"
            exit()

    if args.list_only or args.command_string:
        selected_hosts = get_hosts(file_path)
        # print selected_hosts
        if args.list_only:
            for host in selected_hosts:
                log_and_print(host)
            log_and_print("\nThere were %s hosts listed." % (len(selected_hosts)))
            exit()
        else:
            log_and_print("[INFO]: LOGFILE SET - %s" % (logfile_path))
            log_and_print("[INFO]: USER SET - %s" % (user))
            log_and_print("[INFO]: SSH CONNECT TIMEOUT IS %s seconds" % (connect_timeout))
            log_and_print("[INFO]: THREADS SET - %s" % (workers))
        if args.sudo or args.command_string:
            if args.sudo:
                log_and_print("[INFO]: SUDO IS ON")
            if not args.sudo:
                log_and_print("[INFO]: SUDO IS OFF")

            q = Queue.Queue()

            ssh_to_host(selected_hosts)

            etime=time.time()
            # print etime
            run_time = int(etime-stime)
            # print run_time

            timestamp = str(datetime.timedelta(seconds=run_time))
            # print "you are here >>> ",   successful_logins
            log_and_print("[RESULT]: Succesfully logged into %s/%s hosts and ran your commands in %s secound(s)" % (len(successful_logins), len(selected_hosts), timestamp))
            log_and_print("[RESULT]: There were %s login failures.\n" % (len(failed_logins)) )
            if len(failed_logins) > 0:
                for failed_logins in failed_logins:
                    log_and_print("[RESULT]: Failed to login to %s" % (failed_logins))

    else:
        parser.print_help()
        output = "\n[INFO]: Either -l (list hosts only), or -c (Run cmd string) is required."
        log_and_print(output)