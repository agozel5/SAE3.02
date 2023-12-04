import socket

reply = 'Bonjour, Gozel_Client!'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 11111))
server_socket.listen(1)
print(f"Serveur en écoute sur {'0.0.0.0'}:{11111}")

conn, address = server_socket.accept()
print(f"Connexion établie avec {address}")

conn.send(reply.encode())

while True:
    try:
        # Attente de message du client
        data = conn.recv(11111)
        if not data:
            break

        # Traitement du message
        message = data.decode('utf-8')
        print(f"De {address} : {message}")

        # Réponse du serveur
        if message.lower() == "bye":
            print("Client a demandé la déconnexion.")
            # Fermeture de la connexion avec le client
            conn.close()
            # Nouvelle attente de connexion avec un autre client
            conn, address = server_socket.accept()
            print(f"Connexion établie avec {address}")
            conn.send(reply.encode())
        elif message.lower() == "arret":
            conn.send("Fermeture du serveur et de la socket cliente".encode('utf-8'))
            break
        else:
            reply = input("vous : ")
            conn.send(reply.encode('utf-8'))
            print(f"{reply} envoyé")

    except ConnectionResetError:
        print("Client déconnecté de manière inattendue")
        break

# Fermeture de la connexion avec le client
conn.close()
print("Fermeture de la socket cliente")

server_socket.close()
