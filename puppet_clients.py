# Author: Aleksandar Stoykovski <bavarien362@protonmail.com>

# Description
# The script will run puppet agent client, get the list parse it and compare against
# puppet_hosts file. End result is a file in the format "hostname ssh_portnumber"

import subprocess
import sys
import re
from socket import * 


def get_hosts(host_list):
    """ run bash command to get the host list """
    puppet_command = "sudo su -c \"puppet cert --list --all\""

    puppet_run = subprocess.Popen(puppet_command, 
                                    shell=True, 
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

    puppet_output = puppet_run.stdout.readlines()
    if not puppet_output:
         error = puppet_run.stderr.read()
         print error
         sys.exit(0)

    actual_hosts = open(host_list, "w" )
    for line in puppet_output:
            hosts = line[2:17]
            if hosts.startswith("dashboard") :
                continue
            actual_hosts.write(hosts + "\n")

    actual_hosts.close()
    return host_list
    
def diff():
    """ Check the difference with existing puppet_hosts file """
    host_list = "/tmp/tmp_puppet_hosts_list"
    host_list = "%s" % get_hosts(host_list)
    actual_hosts = open(host_list,"r")
    currnet_hosts = open("/tmp/puppet_hosts", "r")

    actual_host_readlines = actual_hosts.readlines()
    currnet_hosts_read = currnet_hosts.read()

    missing = []
    for line in actual_host_readlines:
        lins = line.strip(" \n")

        if lins not in currnet_hosts_read:
            missing.append(lins)

    return missing

def port_scan():
    """ Do port scan for the common ssh port we have in our env. """
    target = diff()
    if not target:
        print "No new systems found"
        sys.exit(0)
    currnet_hosts = open("/tmp/puppet_hosts", "a")
    new_hosts = []
    try:
        for host in target:
            for port in [22,2022,20122]:
                s = socket(AF_INET, SOCK_STREAM)
                s.settimeout(10)
                result = s.connect_ex((host, port))
                if(result == 0):
                    print "Host %s has Port %d: OPEN" %(host, port)
                    currnet_hosts.write(str(port) + " " + host+"\n")
                    new_hosts.append(host)
                else:
                    print "Host %s Port %d: CLOSED" %(host, port)
                s.close()
        print
        print "List updated with new hosts %s " %  new_hosts
    except Exception:
        pass

def main():
    """ Main function used to call the other functions from the script"""
    port_scan()

if __name__ == '__main__':
    main()