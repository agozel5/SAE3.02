import socket
import threading
import json  # Pour envoyer/recevoir des données au format JSON
import pymysql
import os
import pymysql.err
import sys
import bcrypt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                             QVBoxLayout, QWidget, QTextEdit, QListWidget, 
                             QLineEdit, QMessageBox, QInputDialog, QLabel)



class Server:
    """
    Classe représentant le serveur de l'application de chat.

    Gère les connexions des clients, la distribution des messages, la gestion des salons
    et l'interaction avec la base de données pour l'authentification et l'enregistrement des messages.

    Attributes:
        db_host: L'hôte de la base de données.
        db_user: L'utilisateur de la base de données.
        db_password: Le mot de passe de la base de données.
        db_name: Le nom de la base de données.
        ADMIN_USERNAME: Nom d'utilisateur pour l'administration du serveur.
        ADMIN_PASSWORD: Mot de passe pour l'administration du serveur.
    """
    # Paramètres de connexion à la base de données
    db_host = "localhost"
    db_user = "root"
    db_password = "toto"
    db_name = "application_sae"

    ADMIN_USERNAME = 'admin'  # Définir en tant que variable de classe ou externe
    ADMIN_PASSWORD = 'password'

    def __init__(self, host, port):
        """
        Initialise le serveur avec l'adresse et le port spécifiés.

            host : L'adresse IP sur laquelle le serveur écoute.
            port : Le port sur lequel le serveur écouter.
        """
        self.authenticated = False
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {} # Dictionnaire pour stocker les informations des clients connectés
        self.salons = {"Général": set(), "Blabla": set(), "Comptabilité": set(), "Informatique": set(), "Marketing": set()}
        self.pending_requests = []  # Liste pour stocker les demandes en attente
        # Lancer le thread d'administration pour gérer les commandes d'administration dans le terminal
        admin_thread = threading.Thread(target=self.handle_admin_commands)
        admin_thread.start()
        # Dictionnaire pour stocker l'historique des messages par salon
        self.messages_by_salon = {salon: [] for salon in ["Général", "Blabla", "Comptabilité", "Informatique", "Marketing"]}  # Historique des messages par salon

    def get_db_connection(self):
            """Établit une connexion à la base de données et la retourne."""
            try:
                connection = pymysql.connect(
                    host=self.db_host,
                    user=self.db_user,
                    password=self.db_password,
                    db=self.db_name,
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor
                )
                return connection
            except Exception as e:
                print(f"Erreur lors de la connexion à la base de données : {e}")
                return None

    def start(self):
        """
        Démarre le serveur pour écouter les connexions entrantes.

        Lie le serveur à l'adresse et au port spécifiés et commence à écouter les connexions.
        Pour chaque nouvelle connexion, un thread client est démarré pour gérer la communication.
        """
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Serveur en écoute sur {self.host}:{self.port}")

            while True:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                client_thread.start()

        except Exception as e:
            print(f"Erreur lors du démarrage du serveur : {e}")

    def handle_send_message(self, user_alias, salon_name, message_content):
        """
        Cette méthode gère l'envoi d'un message en l'insérant dans la base de données et en le diffusant au salon spécifié.

            user_alias : L'alias de l'utilisateur envoyant le message.
            salon_name : Le nom du salon où le message est envoyé.
            message_content : Le contenu du message.
        """
        connection = self.get_db_connection()
        if connection is None:
            print("Impossible de se connecter à la base de données.")
            return
        try:
            with connection.cursor() as cursor:
                # S'assurer que le salon existe dans la base de données
                sql_check_salon = "SELECT salon_name FROM salons WHERE salon_name=%s"
                cursor.execute(sql_check_salon, (salon_name,))
                salon_exists = cursor.fetchone()

                # Vérifier si l'utilisateur est dans le salon avant d'insérer le message
                if salon_exists and any(user_alias == alias for alias, sock in self.connections.items() if sock in self.salons[salon_name]):
                    # Insertion du message dans la base de données
                    sql = "INSERT INTO Messages (user_alias, salon_name, message_content, timestamp) VALUES (%s, %s, %s, NOW())"
                    cursor.execute(sql, (user_alias, salon_name, message_content))
                    connection.commit()
                    print("Message inséré avec succès dans la base de données.")
                else:
                    print(f"Utilisateur {user_alias} n'est pas dans le salon {salon_name} ou le salon n'existe pas.")

        except Exception as e:
            print(f"Erreur lors de l'insertion du message : {e}")
        finally:
            connection.close()



    def send_message_history(self, client_socket, salon_name):
        connection = self.get_db_connection()
        with connection.cursor() as cursor:
            sql = "SELECT * FROM Messages WHERE salon_name = %s ORDER BY timestamp ASC"
            cursor.execute(sql, (salon_name,))
            messages = cursor.fetchall()

            for message in messages:
                formatted_message = f"{message['timestamp']} - {message['user_alias']}: {message['message_content']}"
                client_socket.send(formatted_message.encode())  # Ou ajustez selon votre logique d'envoi de messages

        connection.close()

    def broadcast(self, message, salon_name):
        """
        Diffuse un message à tous les utilisateurs d'un salon spécifique.
        """
        if salon_name in self.salons:
            self.messages_by_salon[salon_name].append(message)  # Stocker le message
            for client_socket in list(self.salons[salon_name]):  # Faire une copie de la liste pour éviter les modifications pendant l'itération
                try:
                    client_socket.send(message)
                except Exception as e:
                    print(f"Erreur lors de la diffusion du message dans {salon_name}: {e}")
                    self.salons[salon_name].discard(client_socket)  # Retirer le socket défectueux de la liste des salons
                    
                    # Trouver et retirer le client de la liste des connections si nécessaire
                    for alias, sock in list(self.connections.items()):
                        if sock == client_socket:
                            del self.connections[alias]
                            break
                    try:
                        client_socket.close()  # Tenter de fermer le socket
                    except Exception:
                        pass
        else:
            print(f"Tentative de diffusion dans un salon inexistant : {salon_name}")

    def leave_salon(self, client_socket, salon_name):
        """
        Gère le départ d'un client d'un salon spécifique.
        """
        if salon_name in self.salons and client_socket in self.salons[salon_name]:
            self.salons[salon_name].remove(client_socket)
            print(f"Client {client_socket.getpeername()} a quitté le salon {salon_name}")
        else:
            print(f"Client {client_socket.getpeername()} tente de quitter un salon inexistant ou non rejoint : {salon_name}")



    def handle_client(self, client_socket, addr):
        """
        Gère la communication continue avec un client connecté.
        """
        print(f"Nouvelle connexion de {addr}")
        # Pas de stockage immédiat de la connexion ici, cela se fera après authentificationf
        try:
            while True:
                data = client_socket.recv(1024).decode("utf-8")
                if data:
                    self.process_data(client_socket, addr, data)
        except Exception as e:
            print(f"Erreur avec le client {addr}: {e}")
        finally:
            # Trouvez l'alias associé à la socket
            alias = next((alias for alias, sock in self.connections.items() if sock == client_socket), None)
            if alias:
                # Retirez le client de tous les salons
                for salon in self.salons.values():
                    salon.discard(client_socket)
                # Supprimez le client des connexions
                del self.connections[alias]
            client_socket.close()


    def process_data(self, client_socket, addr, data):
        """
        Traite les données reçues du client en fonction de l'action demandée.

        Cette méthode décode le message JSON reçu, détermine l'action demandée et exécute
        la logique correspondante, telle que l'authentification, l'envoi de messages, etc...
        """
        try:
            data_dict = json.loads(data)
            action = data_dict.get("action")
            user_alias = data_dict.get("alias", None) 

            if action == "auth":
                # Traitement de l'authentification
                alias = data_dict.get("alias")
                print(f"Authentification demandée par {alias}")
                # Vous pouvez répondre au client si nécessaire
                client_socket.sendall(f"Authentification reçue pour le client {alias}".encode("utf-8"))
            
            elif action == "send_private_message":
                # Traitement de l'envoi de messages privés
                sender_alias = data_dict.get("alias")
                recipient_alias = data_dict.get("recipient")
                message_content = data_dict.get("message")
                self.handle_private_message(sender_alias, recipient_alias, message_content)

                # Trouver la socket du destinataire
                recipient_socket = self.get_client_socket(recipient_alias)
                if recipient_socket:
                    try:
                        formatted_message = f"Private from {user_alias}: {message_content}"
                        recipient_socket.send(formatted_message.encode('utf-8'))
                    except Exception as e:
                        print(f"Erreur lors de l'envoi d'un message privé : {e}")
                else:
                    client_socket.sendall("Destinataire non trouvé.".encode("utf-8"))


            elif action == "login":
                 # Traitement de la demande de connexion
                alias = data_dict.get("alias")
                password = data_dict.get("password")

                if alias and password:
                    successful_login, result_message = self.login(alias, password)
                    client_socket.sendall(result_message.encode("utf-8"))
                    if successful_login:  # Si l'authentification est réussie
                        # Ajouter le client au salon Général
                        self.connections[alias] = client_socket  # Stocke la connexion avec l'alias après un login réussi
                        self.join_salon(client_socket, "Général")
                        client_socket.sendall("Ajouté au salon Général".encode("utf-8"))
                        self.update_user_alias(client_socket, alias)
                else:
                    client_socket.sendall("Veuillez fournir l'alias et le mot de passe.".encode("utf-8"))

            elif action == "send_message":
            # Extraire les données du message
                user_alias = data_dict.get("alias")
                salon_name = data_dict.get("salon")
                message_content = data_dict.get("message")

                if message_content and salon_name in self.salons:
                    # Formattez le message comme avant et diffusez-le
                    formatted_message = f"{user_alias} dit : {message_content}"
                    self.broadcast(formatted_message.encode('utf-8'), salon_name)

                    # Enregistrer le message dans la base de données
                    self.handle_send_message(user_alias, salon_name, message_content)
                else:
                    client_socket.sendall("Message ou salon non spécifié.".encode("utf-8"))

            elif action == "signup":
                nom = data_dict.get("nom")
                prenom = data_dict.get("prenom")
                alias = data_dict.get("alias")
                password = data_dict.get("password")

                if nom and prenom and alias and password:
                    result = self.signup(data_dict)
                    client_socket.sendall(result.encode("utf-8"))
                    if result == "Inscription réussie":
                        print(f"Inscription réussie de {nom} {prenom} {alias} {password}")
                else:
                    client_socket.sendall("Veuillez fournir toutes les informations d'inscription.".encode("utf-8"))
            
            elif action == "join_salon":
                salon_name = data_dict.get("salon_name")
                if salon_name in self.salons:
                    self.join_salon(client_socket, salon_name)
                    client_socket.sendall(f"Vous avez rejoint le salon {salon_name}".encode("utf-8"))
                else:
                    client_socket.sendall("Salon non trouvé".encode("utf-8"))

            elif action == "leave_salon":
                salon_name = data_dict.get("salon_name")
                if salon_name in self.salons and client_socket in self.salons[salon_name]:
                    self.leave_salon(client_socket, salon_name)
                    client_socket.sendall(f"Vous avez quitté le salon {salon_name}".encode("utf-8"))
                else:
                    client_socket.sendall("Erreur lors de la tentative de quitter le salon".encode("utf-8"))

            elif action == "request_join_salon":
                salon_name = data_dict.get("salon_name")
                alias = data_dict.get("alias")

                # Autorisation immédiate pour les salons "Général" et "Blabla"
                if salon_name in ["Général", "Blabla"]:
                    self.join_salon(client_socket, salon_name)
                    client_socket.sendall(f"Vous avez rejoint le salon {salon_name}".encode("utf-8"))

                # Autorisation en attente pour les autres salons
                elif salon_name in ["Comptabilité", "Informatique", "Marketing"]:
                    print(f"{alias} demande à rejoindre le salon {salon_name}")
                    self.pending_requests.append((client_socket, alias, salon_name))
                    client_socket.sendall(f"Demande envoyée pour rejoindre le salon {salon_name}. En attente d'approbation.".encode("utf-8"))

                else:
                    client_socket.sendall("Salon non reconnu".encode("utf-8"))

            else:
                client_socket.sendall(f"Action non reconnue : {action}".encode("utf-8"))
            
        except json.JSONDecodeError:
            print("Erreur de décodage JSON")
            client_socket.sendall("Erreur de décodage JSON".encode("utf-8"))

    def handle_private_message(self, sender_alias, recipient_alias, message_content):
        """
        Gère l'insertion d'un message privé dans la base de données.
        """
        connection = self.get_db_connection()
        try:

            with connection.cursor() as cursor:
                # Insertion du message privé dans la base de données
                sql = "INSERT INTO PrivateMessages (sender_alias, recipient_alias, message_content) VALUES (%s, %s, %s)"
                cursor.execute(sql, (sender_alias, recipient_alias, message_content))
                connection.commit()
                print("Message privé inséré avec succès dans la base de données.")

        except Exception as e:
            print(f"Erreur lors de l'insertion du message privé : {e}")
        finally:
            connection.close()

    def handle_admin_commands(self):
        """
        Gère les commandes administratives du serveur.

        Permet à l'administrateur d'exécuter des commandes dans le terminal pour gérer le serveur et les utilisateurs,
        telle que l'acceptation ou le refus de demandes de participation à des salons,
        et le bannissement d'utilisateurs.
        """
        while True:
            # Vérifie si l'administrateur est authentifié
            if not self.authenticated:
                print("Veuillez vous authentifier pour effectuer des commandes.")
                username = input("Nom d'utilisateur : ")
                password = input("Mot de passe : ")
                if username == self.ADMIN_USERNAME and password == self.ADMIN_PASSWORD:
                    print("Authentification réussie. Vous pouvez maintenant exécuter des commandes.")
                    self.authenticated = True
                else:
                    print("Échec de l'authentification.")
                    continue

            # Traitement des commandes administratives
            admin_input = input("Entrez une commande (ex. 'accepter', 'refuser'): ")
            parts = admin_input.split()
            if len(parts) == 2 and parts[1].isdigit():
                index = int(parts[1]) - 1  # -1 car l'indexation humaine commence généralement à 1
                if 0 <= index < len(self.pending_requests):
                    client_socket, alias, salon_name = self.pending_requests[index]
                    if parts[0].lower() == "accepter":
                        self.approve_request(client_socket, salon_name)
                        print(f"{alias} a été accepté dans le salon {salon_name}.")
                    elif parts[0].lower() == "refuser":
                        self.deny_request(client_socket, salon_name)
                        print(f"{alias} a été refusé l'accès au salon {salon_name}.")
                    # Retirer la demande traitée de la liste des demandes en attente
                    self.pending_requests.pop(index)
                else:
                    print("Numéro de demande invalide.")
            else:
                print("Commande non reconnue.")
            
            command = input("Entrer une commande kick/ban/kill: ").strip().lower()
            commands = command.split()

            if len(commands) >= 2:
                action, user_alias = commands[0], commands[1]

                if action == "kick":
                    self.kick_user(user_alias)
                elif action == "ban" and len(commands) >= 3:
                    user_alias = commands[1]
                    reason = " ".join(commands[2:])  # Rejoindre tous les éléments de la raison
                    self.ban_user(user_alias, reason)
                else:
                    print("Unknown command or not enough arguments.")

            elif command == "kill":
                self.kill_server()
            else:
                print("Unknown command.")

    def kick_user(self, user_alias):
        """
        Exclut un utilisateur du serveur en fermant sa connexion.
        """
        if user_alias in self.connections:
            client_socket = self.connections[user_alias]
            try:
                # Envoie un message à l'utilisateur et ferme sa connexion
                client_socket.sendall("You have been kicked out!".encode())
                client_socket.close()
                print(f"User {user_alias} has been kicked.")
                del self.connections[user_alias]  # Supprime l'utilisateur des connexions
            except Exception as e:
                print(f"Error kicking user {user_alias}: {e}")
        else:
            print(f"No active connection found for alias {user_alias}")



    def ban_user(self, user_alias, reason):
        """
        Bannit un utilisateur du serveur, en supprimant ses détails de la base de données et en fermant sa connexion.
        """
        connection = self.get_db_connection()
        try:

            with connection.cursor() as cursor:
                # Vérifier si l'utilisateur existe dans la table Utilisateurs
                cursor.execute("SELECT alias FROM Utilisateurs WHERE alias = %s", (user_alias,))
                user_exists = cursor.fetchone()
                
                if not user_exists:
                    print(f"L'utilisateur {user_alias} n'existe pas et ne peut être banni.")
                    return  # Si l'utilisateur n'existe pas, arrêtez la méthode ici.

                # Ajouter l'utilisateur à BannedUsers (S'il existe déjà, il sera mis à jour)
                cursor.execute("INSERT INTO BannedUsers (alias, ban_reason) VALUES (%s, %s)", (user_alias, reason))
                connection.commit()

                # Supprimer l'utilisateur de Utilisateurs
                cursor.execute("DELETE FROM Utilisateurs WHERE alias = %s", (user_alias,))
                connection.commit()

                # Envoi de la notification de bannissement au client
                if user_alias in self.connections:
                    client_socket = self.connections[user_alias]
                    ban_notification = f"You have been banned for the following reason: {reason}"
                    client_socket.send(ban_notification.encode('utf-8'))
                    client_socket.close()
                    del self.connections[user_alias]

                print(f"L'utilisateur {user_alias} a été banni avec succès.")

        except Exception as e:
            print(f"Erreur lors du bannissement de l'utilisateur {user_alias}: {e}")
            connection.rollback()
        finally:
            connection.close()


    def kill_server(self):
        """
        Arrête le serveur en fermant toutes les connexions actives et en terminant le processus serveur.
        """
        # Avertir tous les utilisateurs
        for alias, client_socket in self.connections.items():
            try:
                client_socket.send("Server is shutting down!".encode())
            except Exception as e:
                print(f"Error closing client connection for {alias}: {e}")
            finally:
                client_socket.close()

        # arrête le serveur
        self.server_socket.close()
        print("Server has been shut down.")
        os._exit(0)


    def approve_request(self, index):
        """
        Approuve la demande d'accès à un salon pour un client.
        """
        # Assure que l'index est valide et accepte laa demande
        if 0 <= index < len(self.pending_requests):
            client_socket, alias, salon_name = self.pending_requests.pop(index)
            self.join_salon(client_socket, salon_name)
            message = f"Accès au salon {salon_name} approuvé."
            try:
                client_socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Erreur lors de l'envoi du message d'approbation : {e}")
            print(f"{alias} a été accepté dans le salon {salon_name}.")
        else:
            print("Index invalide lors de l'approbation de la demande.")

    def deny_request(self, index):
        """
        Refuse la demande d'accès à un salon pour un client.
        """
        if 0 <= index < len(self.pending_requests):
            client_socket, alias, salon_name = self.pending_requests[index]
            message = f"Accès au salon {salon_name} refusé pour {alias}."
            client_socket.send(message.encode('utf-8'))
            self.pending_requests.pop(index)
            print(f"{alias} a été refusé l'accès au salon {salon_name}.")
        else:
            print("Index invalide lors du refus de la demande.")


    def join_salon(self, client_socket, salon_name):
        """
        Ajoute un client à un salon et lui envoie l'historique des messages de ce salon.
        """
        self.salons[salon_name].add(client_socket)
        # Envoi l'historique des messages pour ce salon
        message_history = self.messages_by_salon[salon_name]
        for message in message_history:
            try:
                client_socket.send(message)  # Envoye chaque message de l'historique
            except Exception as e:
                print(f"Erreur lors de l'envoi du message : {e}")
        print(f"Client {client_socket.getpeername()} a rejoint le salon {salon_name} et a reçu l'historique des messages.")

    def approve_request(self, client_socket, salon_name):
        # Méthode pour approuver une demande d'accès à un salon
        self.join_salon(client_socket, salon_name)
        client_socket.sendall(f"Accès au salon {salon_name} approuvé".encode("utf-8"))

    def distribute_message(self, sender_socket, message_data):
        """
        Distribue un message de l'expéditeur à tous les autres clients d'un salon.
        """
        salon = message_data.get("salon")
        if salon in self.salons:
            for client_socket in self.salons[salon]:
                if client_socket != sender_socket:
                    try:
                        client_socket.sendall(json.dumps(message_data).encode("utf-8"))
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du message : {e}")

     # Ajout de cette méthode pour obtenir la socket du client
    
    def get_client_socket(self, alias):
        return self.connections.get(alias)


    def login(self, alias, password):
        """
        Vérifie les informations de connexion d'un utilisateur et l'authentifie si elles sont correctes.
        """
        connection = self.get_db_connection()

        try:
            with connection.cursor() as cursor:
                # Récupérer le mot de passe haché de l'utilisateur
                sql = "SELECT mot_de_passe FROM utilisateurs WHERE alias=%s"
                cursor.execute(sql, (alias,))
                result = cursor.fetchone()

                if result:
                    # Récupérer le mot de passe haché stocké
                    hashed_password = result['mot_de_passe']
                    # Vérifier si le mot de passe fourni correspond au hachage
                    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                        return True, "Connexion réussie"
                    else:
                        return False, "Alias ou mot de passe incorrect"
                else:
                    return False, "Alias ou mot de passe incorrect"
        except Exception as e:
            print(f"Erreur lors de la connexion à la base de données : {e}")
            return False, "Erreur de connexion à la base de données"
        finally:
            connection.close()

    def signup(self, user_data):
        """
        Insère un nouvel utilisateur dans la base de données après avoir haché son mot de passe.
        """
        # Connexion à la base de données
        connection = self.get_db_connection()

        try:
            with connection.cursor() as cursor:
                # Vérifie si l'alias est déjà utilisé
                sql_check_alias = "SELECT * FROM utilisateurs WHERE alias=%s"
                cursor.execute(sql_check_alias, (user_data.get("alias"),))
                result = cursor.fetchone()

                if result:
                    return "Alias déjà utilisé"
                else:
                    # Hache le mot de passe avant de l'insérer
                    hashed_password = bcrypt.hashpw(user_data.get("password").encode('utf-8'), bcrypt.gensalt())

                    # Insérer les données d'inscription dans la base de données
                    sql_insert = "INSERT INTO utilisateurs (nom, prenom, alias, mot_de_passe, date_creation) VALUES (%s, %s, %s, %s, NOW())"
                    cursor.execute(sql_insert, (user_data.get("nom"), user_data.get("prenom"),
                                                user_data.get("alias"), hashed_password.decode('utf-8')))
                    connection.commit()

                    return "Inscription réussie"
        except Exception as e:
            print(f"Erreur lors de l'inscription dans la base de données : {e}")
            return "Erreur d'inscription dans la base de données"
        finally:
            connection.close()
        
    def update_user_alias(self, client_socket, alias):
        for key, value in self.connections.items():
            if value == client_socket:
                del self.connections[key]
                break
        self.connections[alias] = client_socket

def start_server_logic(server):
    server.start()  # Utilisez la méthode start de votre classe Server

############################################
class ControlPanelWindow(QMainWindow):
    """
    Fenêtre du panneau de contrôle du serveur.

    Cette interface graphique permet à un administrateur de gérer le serveur,
     compris le bannissement ou l'exclusion d'utilisateurs, l'arrêt du serveur, etc.
    """
    def __init__(self, server):
        super().__init__()
        self.server = server  # Instance du serveur
        self.initUI()

    def initUI(self):
        # Configuration de l'interface utilisateur
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Zone de journalisation du serveur
        self.server_log = QTextEdit()
        self.server_log.setReadOnly(True)
        layout.addWidget(self.server_log)


        # Bouton pour exclure un utilisateur
        self.kick_button = QPushButton("Kick User")
        self.kick_button.clicked.connect(self.kick_user)
        layout.addWidget(self.kick_button)

        
        # Ajout d'un espace coloré
        colored_space = QWidget()  # Création d'un widget vide pour agir comme un espace
        colored_space.setFixedHeight(5)  # Définition de la hauteur de l'espace
        colored_space.setStyleSheet("background-color: #FFA07A;")  # Définition de la couleur de l'espace
        layout.addWidget(colored_space)  # Ajout de l'espace coloré au layout

        # Bouton pour bannir un utilisateur
        self.ban_button = QPushButton("Ban User")
        self.ban_button.clicked.connect(self.ban_user)
        layout.addWidget(self.ban_button)


        # Ajout d'un espace coloré
        colored_space = QWidget()  
        colored_space.setFixedHeight(5)  
        colored_space.setStyleSheet("background-color: #FFA07A;") 
        layout.addWidget(colored_space)  

        # Bouton pour arrêter le serveur
        self.kill_button = QPushButton("Kill Server")
        self.kill_button.clicked.connect(self.kill_server)
        layout.addWidget(self.kill_button)


        # Ajout d'un espace coloré
        colored_space = QWidget() 
        colored_space.setFixedHeight(5)  
        colored_space.setStyleSheet("background-color: #FFA07A;")  
        layout.addWidget(colored_space)  
           
            # Bouton pour avertir les utilisateurs
        self.avertir_utilisateur_button = QPushButton("Warning User", self)
        self.avertir_utilisateur_button.clicked.connect(self.avertir_utilisateur)
        layout.addWidget(self.avertir_utilisateur_button)

        
        # Ajout d'un espace coloré
        colored_space = QWidget()  
        colored_space.setFixedHeight(10) 
        colored_space.setStyleSheet("background-color: #000000;")  
        layout.addWidget(colored_space)  


        # Bouton pour gérer les demandes d'adhésion
        self.manage_requests_button = QPushButton("Manage participation requests", self)
        self.manage_requests_button.clicked.connect(self.manage_requests)
        layout.addWidget(self.manage_requests_button)

        self.setWindowTitle('Server')
        self.setGeometry(300, 300, 600, 400)
        #Application du style css
        apply_dark_stylesheet(self)
        self.show()
    
    def set_server(self, server):
        self.server = server
        server.control_panel = self

    def kick_user(self):
        """
        Envoie une commande au serveur pour exclure un utilisateur spécifié.
        """
        user_alias, okPressed = QInputDialog.getText(self, "Kick User", "User alias:")
        if okPressed and user_alias:
            self.server.kick_user(user_alias)
            self.update_logs(f"Kicked user: {user_alias}")

    def ban_user(self):
        user_alias, okPressed = QInputDialog.getText(self, "Ban User", "Alias de l'utilisateur:")
        reason, okPressed = QInputDialog.getText(self, "Ban User", "Entrer la raison:")
        if okPressed and user_alias:
            self.server.ban_user(user_alias, reason)
            self.update_logs(f"Banned user: {user_alias} for reason: {reason}")

    def kill_server(self):
        self.server.kill_server()
        self.update_logs("Server is shutting down...")
        QApplication.quit()
    
    def manage_requests(self):
        # Créer une nouvelle fenêtre ou un dialogue pour gérer les demandes
        self.request_management_window = RequestManagementWindow(self.server)
        self.request_management_window.show()
    
    def avertir_utilisateur(self):
        # Demander à l'utilisateur et à la raison à partir d'une boîte de dialogue
        utilisateur_alias, okPressed = QInputDialog.getText(self, "Avertir User", "Alias de l'utilisateur:")
        raison, okPressed = QInputDialog.getText(self, "Avertir Utilisateur", "Entrer la raison:")

        if okPressed and utilisateur_alias and raison:
            # Appeler la méthode avertir_utilisateur avec les arguments requis
            if self.avertir_utilisateur_db(utilisateur_alias, raison):
                self.afficher_message_succes("Utilisateur averti avec succès.")  # Passer un message ici
            else:
                # Afficher un message d'erreur si nécessaire
                self.afficher_message_erreur()

    def avertir_utilisateur_db(self, utilisateur_alias, raison):
        """
        Avertit un utilisateur en enregistrant l'avertissement dans la base de données et en envoyant un message.
        """
        connection = self.server.get_db_connection()
        if connection is not None:
            try:
                with connection.cursor() as cursor:
                    # Vérifiez si l'utilisateur existe dans la base de données
                    utilisateur_query = "SELECT * FROM Utilisateurs WHERE alias = %s"
                    utilisateur_data = (utilisateur_alias,)
                    cursor.execute(utilisateur_query, utilisateur_data)
                    utilisateur_result = cursor.fetchone()

                    if utilisateur_result:  # Si l'utilisateur existe
                        # Enregistrez l'avertissement dans la base de données
                        insert_avertissement_query = "INSERT INTO Avertissements (utilisateur_alias, raison) VALUES (%s, %s)"
                        insert_avertissement_data = (utilisateur_alias, raison)
                        cursor.execute(insert_avertissement_query, insert_avertissement_data)
                        connection.commit()

                        # Si l'utilisateur est connecté, envoyez-lui un message d'avertissement
                        if utilisateur_alias in self.server.connections:
                            client_socket = self.server.connections[utilisateur_alias]
                            message_avertissement = {"type": "warning", "content": f"Vous avez reçu un avertissement pour la raison suivante : {raison}"}
                            client_socket.sendall(json.dumps(message_avertissement).encode('utf-8'))

                        return True  # Succès
                    return False  # Échec si l'utilisateur n'existe pas
            except Exception as e:
                print(f"Erreur lors de l'avertissement de l'utilisateur : {str(e)}")
                return False  # Échec
            finally:
                connection.close()

    def afficher_message_succes(self, message):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText(message)
        msgBox.setWindowTitle("Succès")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.exec()

    def update_logs(self, message):
        """
        Met à jour les logs dans l'interface graphique du panneau de contrôle.
        """
        self.server_log.append(message)
        
############################################
class RequestManagementWindow(QMainWindow):
    """
    Fenêtre pour gérer les demandes d'adhésion au salon.

    Permet aux administrateurs de voir et de répondre aux demandes de participation des utilisateurs.
    """
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.initUI()

    def initUI(self):
        """
        Configure l'interface utilisateur pour la gestion des demandes d'adhésion.
        """
        self.setWindowTitle('Membership request')
        self.setGeometry(300, 300, 350, 300)
        layout = QVBoxLayout()

        #application du style
        apply_dark_stylesheet(self)

        # Liste des demandes
        self.request_list = QListWidget()
        self.update_request_list()
        layout.addWidget(self.request_list)

        # Boutons pour accepter ou refuser la demande
        accept_button = QPushButton("Accept")
        accept_button.clicked.connect(self.accept_request)
        layout.addWidget(accept_button)

        reject_button = QPushButton("Reject")
        reject_button.clicked.connect(self.reject_request)
        layout.addWidget(reject_button)

        # Set layout
        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def update_request_list(self):
        """
        Met à jour la liste des demandes d'adhésion en attente.
        """
        self.request_list.clear()
        for idx, (_, alias, salon_name) in enumerate(self.server.pending_requests):
            self.request_list.addItem(f"{idx + 1}: {alias} requests to join {salon_name}")

    def accept_request(self):
        """
        Accepte la demande d'adhésion sélectionnée.
        """
        selected_index = self.request_list.currentRow()
        if selected_index != -1 and 0 <= selected_index < len(self.server.pending_requests):
            # Récupérez la demande sélectionnée et retirez-la de la liste des demandes en attente
            client_socket, alias, salon_name = self.server.pending_requests.pop(selected_index)

            # Appeler approve_request avec les bons arguments
            self.server.approve_request(client_socket, salon_name)

            # Mettez à jour la liste des demandes après avoir approuvé la demande
            self.update_request_list()
        else:
            print("Aucune demande sélectionnée ou index invalide.")
    
    def reject_request(self):
        """
        Rejette la demande d'adhésion sélectionnée.
        """
        selected_index = self.request_list.currentRow()
        if selected_index != -1:  # Assurez-vous qu'un élément est bien sélectionné
            self.server.deny_request(selected_index)
            self.update_request_list()
############################################
class AvertissementWindow(QMainWindow):
    """
    Fenêtre pour envoyer des avertissements aux utilisateurs.

    Permet aux administrateurs d'envoyer des avertissements aux utilisateurs pour diverses raisons.
    """
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.initUI()

    def initUI(self):
        """
        Configure l'interface utilisateur pour envoyer des avertissements.
        """
        layout = QVBoxLayout()

        # Champ pour sélectionner l'utilisateur
        self.utilisateur_label = QLabel("Alias de l'utilisateur:")
        self.utilisateur_input = QLineEdit()
        layout.addWidget(self.utilisateur_label)
        layout.addWidget(self.utilisateur_input)

        # Champ pour entrer la raison de l'avertissement
        self.raison_label = QLabel("Raison de l'avertissement:")
        self.raison_input = QTextEdit()
        layout.addWidget(self.raison_label)
        layout.addWidget(self.raison_input)

        # Bouton pour envoyer l'avertissement
        send_button = QPushButton("Envoyer l'avertissement")
        send_button.clicked.connect(self.envoyer_avertissement)
        layout.addWidget(send_button)

        # layout
        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

    def envoyer_avertissement(self):
        """
        Envoie un avertissement à l'utilisateur spécifié avec une raison donnée.
        """
        utilisateur_alias = self.utilisateur_input.text()
        raison = self.raison_input.toPlainText()

        # Vérifier si l'utilisateur existe et si un avertissement similaire a déjà été envoyé
        if self.server.avertir_utilisateur(utilisateur_alias, raison):
            QMessageBox.information(self, "Succès", "Utilisateur averti avec succès")
        else:
            QMessageBox.warning(self, "Échec", "Impossible d'avertir l'utilisateur")
        self.close()
    

############################################
class StartServerWindow(QMainWindow):
    """
    Fenêtre pour démarrer le serveur.

    Cette interface permet à l'utilisateur de démarrer le serveur avant de passer à l'interface d'authentification.
    """
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.initUI()

    def initUI(self):
        """
        Configure l'interface utilisateur pour démarrer le serveur.
        """
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Start Server Button
        self.start_button = QPushButton("Start Server", self)
        self.start_button.clicked.connect(self.start_server)
        layout.addWidget(self.start_button)

        # Set window properties
        self.setWindowTitle('Start Server')
        self.setGeometry(500, 100, 400, 150)
        #Application du style css
        apply_dark_stylesheet(self)
        self.show()

    def start_server(self):
        # Démarre le serveur et ouvre la fenêtre d'authentification.
        server_thread = threading.Thread(target=start_server_logic, args=(self.server,))
        server_thread.start()

        # Afficher la fenêtre d'authentification une fois le serveur démarré
        self.auth_window = AuthenticationWindow(self.server)
        self.auth_window.show()
        self.close()  # Fermer la fenêtre de démarrage

##################AUTHENTIFICATION##########################
        
class AuthenticationWindow(QMainWindow):
    """
    Fenêtre pour l'authentification de l'administrateur du serveur dans l'interface graphique

    Permet l'authentification avant d'accéder au panneau de contrôle du serveur.
    """
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.initUI()

    def initUI(self):
        """
        Configure l'interface utilisateur pour l'authentification.
        """
        # Créer un widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Champs de nom d'utilisateur et de mot de passe
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Bouton de connexion
        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.login)

        # Ajout des widgets
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        self.setWindowTitle('Authenticate')
        self.setGeometry(300, 300, 400, 200)
        #Application du style css
        apply_dark_stylesheet(self)
        self.show()


    def login(self):
        """
        Gère la tentative de connexion de l'utilisateur.
        """
        username = self.username_input.text()
        password = self.password_input.text()

        if username == "" or password == "":
            QMessageBox.warning(self, "Champs manquants", "Veuillez remplir les champs")
        elif username == self.server.ADMIN_USERNAME and password == self.server.ADMIN_PASSWORD:
            print("Authentication successful!")
            # Ouvrir la fenêtre de contrôle principal du serveur
            self.control_panel_window = ControlPanelWindow(self.server)  # Créer la fenêtre
            self.control_panel_window.show()  # Montrer la fenêtre
            self.close()  # Fermer la fenêtre d'authentification
        else:
            QMessageBox.warning(self, "Échec de l'authentification", "Le mot de passe et/ou le username est mauvais")
            print("Authentication failed.")

#Style Css : Ajout du couleur gris dans tous les interfaces
def apply_dark_stylesheet(widget):
    widget.setStyleSheet("""
    QWidget {
        background-color: #333333;
        color: #ffffff;
    }
    QTextEdit, QLineEdit {
        border: 1px solid #888888;
        background-color: #444444;
        color: #ffffff;
    }
    QPushButton {
        background-color: #555555;
        border: 1px solid #666666;
        padding: 5px;
        border-radius: 2px;
        color: #ffffff;
        min-height: 30px;
        min-width: 100px;
    }
    QPushButton:hover {
        background-color: #666666;
    }
    QPushButton:pressed {
        background-color: #777777;
    }
    """)

def main():
    app = QApplication(sys.argv)

    server_instance = Server('127.0.0.1', 12345) 

    # Créer et montrer la fenêtre de démarrage du serveur
    start_server_window = StartServerWindow(server_instance)  
    start_server_window.show()  # Assurez-vous de montrer la fenêtre

    sys.exit(app.exec_())  # Commencer la boucle d'événements

if __name__ == '__main__':
    main()