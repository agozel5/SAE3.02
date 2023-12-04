import socket
print("bonjour")

client_socket = socket.socket()
print("La création à établie")

client_socket.connect(('127.0.0.1',2801 ))
print("connection établie")

message = 'Ca va est toi?'
client_socket.send(message.encode())
print("La connection établie")

reply = client_socket.recv(1024).decode()
client_socket.close()
