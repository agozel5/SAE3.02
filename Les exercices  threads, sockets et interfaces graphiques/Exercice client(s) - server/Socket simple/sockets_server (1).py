import socket
server_socket = socket.socket()
print("La création à été établie")

server_socket.bind(('0.0.0.0', 2801))
server_socket.listen(1)
print("En attente de connection")

conn, address = server_socket.accept()
print("Etablissement de la conncetion")

message = conn.recv(1024).decode()
print("Réception des données")

reply = 'Salut ça va? '
conn.send(reply.encode())
conn.close()
server_socket.close()