import socket

message = 'Bonjour, Gozel_Server!'

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 11111))
print("Connexion établie...")

reply = client_socket.recv(1024).decode()
print(f'Serveur : {reply}')

while True:
    user_input = input("vous (bye/arret pour quitter) : ")
    client_socket.send(user_input.encode('utf-8'))

    if user_input.lower() == "bye":
        print("Déconnexion du client.")
        client_socket.close()
        break
    elif user_input.lower() == "arret":
        response = client_socket.recv(11111).decode('utf-8')
        print(response)
        client_socket.close()
        break

    server_reply = client_socket.recv(1024).decode('utf-8')
    print(f"Serveur : {server_reply}")

client_socket.close()
