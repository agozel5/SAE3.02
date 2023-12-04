import socket
import threading

clients = []
j = 1

def ecoute(conn, addr):
    global j
    while j == 1:
        message = conn.recv(1024).decode()
        if message == "arret":
            reply = "Fin"
            conn.send(reply.encode())
            conn.close()
            clients.remove((conn, addr))
            if not clients:
                j = 2
        elif message == "bye":
            print(f"Client {addr} a quitté la conversation.")
            reply = "Fin"
            conn.send(reply.encode())
            conn.close()
            clients.remove((conn, addr))
            break
        else:
            #print(f"Message reçu du client {addr}: {message}")
            # Envoyer le message à tous les autres clients
            for client, client_addr in clients:
                if (client, client_addr) != (conn, addr):
                    client.send(f"Client {addr}: {message}".encode())

def accepter_connexions():
    global j
    while j == 1:
        print("En attente de clients...")
        conn, address = server_socket.accept()
        print(f"Nouveau client connecté : {address}")
        clients.append((conn, address))
        t = threading.Thread(target=ecoute, args=(conn, address))
        t.start()

def main():
    global j
    t_accept = threading.Thread(target=accepter_connexions)
    t_accept.start()

    t_accept.join()  # Attend que le thread d'acceptation se termine

    # Arrêter tous les clients
    for client in clients:
        client.send("arret".encode())
        client.close()

    server_socket.close()

if __name__ == "__main__":
    server_socket = socket.socket()
    server_socket.bind(('127.0.0.1', 5546))
    server_socket.listen()

    main()
