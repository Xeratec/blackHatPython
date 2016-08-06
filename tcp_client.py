#!/usr/bin/python


import socket

target_host = "127.0.0.1"
target_port = 9999

# create socket objekt
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to client
client.connect((target_host, target_port))

# send some data
client.send("ls -al\n")

#recieve some data
response = client.recv(4096)

print response
