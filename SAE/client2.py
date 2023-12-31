import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox, QTextEdit
import socket
import json
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import QComboBox
from PyQt5.QtGui import QFont


class ClientThread(QThread):
    """
    Un thread client pour gérer la réception des messages du serveur.

    Cette classe hérite de QThread pour gérer la réception des messages
    de manière asynchrone. Elle émet un signal chaque fois qu'un message est reçu.

    Attributes:
        message_received (pyqtSignal): Signal émis lorsqu'un message est reçu.
        client_socket (socket): Le socket client connecté au serveur.
    """

    # Signal pour notifier quand un message est reçu
    message_received = pyqtSignal(str)

    def __init__(self, client_socket):
        """
        Initialise le thread client avec un socket client.

        client_socket (socket): Le socket client pour la communication avec le serveur.
        """
        super().__init__()
        self.client_socket = client_socket

    def run(self):
        """
        Exécute le thread qui écoute les messages entrants du serveur.

        Cette méthode est appelée lorsque le thread est démarré avec .start().
        Elle écoute en continu les messages du serveur et émet un signal
        lorsque des messages sont reçus.
        """
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    self.message_received.emit(message)
            except Exception as e:
                print(f"Erreur dans ClientThread: {e}")
                
                break

class ChatClient(QWidget):
    """
    Interface client pour l'application de chat.

    Cette classe gère la fenêtre principale de l'application client de chat.
    Elle initialise l'interface utilisateur, gère la connexion au serveur et
    l'affichage des messages reçus.

    Attributes:
        alias (str): L'alias de l'utilisateur.
        client_socket (socket): Le socket client connecté au serveur.
        current_salon (str): Le salon de chat actuel.
        message_history (dict): Un historique des messages pour chaque salon.
    """
    def __init__(self, alias, client_socket):
        """
        Initialise le client de chat avec les informations utilisateur et le socket client.
        """
        super().__init__()
        self.alias = alias # Alias de l'utilisateur
        self.client_socket = client_socket # Socket client pour la communication avec le serveur
        self.init_ui() # Initialise l'interface utilisateurv
        self.current_salon = None 
        self.current_salon = "Général" # Salon actuel par défaut

        self.setGeometry(300, 300, 550, 400)  # Définit la géométrie de la fenêtre
        self.setMinimumSize(700, 700)  # Définit la taille minimale de la fenêtre
        apply_stylesheet(self) # Applique le style à la fenêtre

        # Création et démarrage du thread client pour écouter les messages du serveur
        self.client_thread = ClientThread(self.client_socket)
        self.client_thread.message_received.connect(self.display_message)
        self.client_thread.start()

        # Envoi de l'alias au serveur pour l'authentification
        self.client_socket.send(json.dumps({"action": "auth", "alias": self.alias}).encode('utf-8'))

        # Initialisation de l'historique des messages
        self.message_history = {"Général": [], "Blabla": [], "Comptabilité": [], "Informatique": [], "Marketing": []}

    def init_ui(self):
        # Créez un QLabel pour le texte de bienvenue en gras
        label_welcome = QLabel("BIENVENUE DANS L'APPLICATION", self)
        font = QFont()  # Crée une instance de QFont
        font.setBold(True)  # Met le texte en gras
        font.setPointSize(12)  # Vous pouvez ajuster la taille de la police si nécessaire
        label_welcome.setFont(font)  # Applique la police au label
        label_welcome.setAlignment(Qt.AlignCenter)  # Aligner le texte au centre
        # Créez un QTextEdit pour le chat
        self.text_chat = QTextEdit(self)
        self.text_chat.setReadOnly(True)

        # Ajout pour les messages
        self.entry_message = QLineEdit(self)
        self.entry_message.setPlaceholderText("Entrez votre message:")

        self.button_send = QPushButton('Envoyer', self)
        self.button_send.clicked.connect(self.send_message)

        # Ajout pour les messages privés
        self.entry_recipient = QLineEdit(self)
        self.entry_recipient.setPlaceholderText("Alias de l'admin destinataire:")

        self.button_send_private = QPushButton('Envoyer Privé', self)
        self.button_send_private.clicked.connect(self.send_private_message)

        self.entry_private_message = QLineEdit(self)
        self.entry_private_message.setPlaceholderText("Entrez votre message privé ici:")

        # Création du bouton Quitter
        self.quitter_button = QPushButton('Quitter', self)
        self.quitter_button.clicked.connect(self.quitter_application)
        self.quitter_button.setFixedSize(150, 44)  # Ajuster la taille du bouton

        # Créer un horizontal layout pour le bouton Quitter, pour le positionner en bas à droite
        bottomRightLayout = QHBoxLayout()
        bottomRightLayout.addStretch(1)  # Ajoute un espace flexible qui pousse le contenu à droite
        bottomRightLayout.addWidget(self.quitter_button)  # Ajoute le bouton à l'extrême droite

        # Ajout d'un QTextEdit pour les notifications
        self.text_notifications = QTextEdit(self)
        self.text_notifications.setReadOnly(True)
        self.text_notifications.setFixedHeight(100)  # Fixer la hauteur pour les notifications

        # Sélecteur de salon et boutons pour rejoindre/quitter les salons
        self.salon_selector = QComboBox(self)
        self.salon_selector.addItems(["Général", "Blabla", "Comptabilité", "Informatique", "Marketing"])

        self.join_salon_button = QPushButton('Rejoindre Salon', self)
        self.join_salon_button.clicked.connect(self.join_salon)

        self.leave_salon_button = QPushButton('Quitter Salon', self)
        self.leave_salon_button.clicked.connect(self.leave_salon)

        # Layout pour la gestion des salons
        salon_layout = QHBoxLayout()
        salon_layout.addWidget(self.salon_selector)
        salon_layout.addWidget(self.join_salon_button)
        salon_layout.addWidget(self.leave_salon_button)

        # Layout pour les éléments inférieurs de l'UI, incluant le bouton Quitter en bas à droite
        bottom_layout = QVBoxLayout()
        bottom_layout.addLayout(salon_layout)
        bottom_layout.addLayout(bottomRightLayout)  # Utilisez le bottomRightLayout pour le bouton Quitter

        # Layout principal
        layout = QVBoxLayout()
        layout.addWidget(label_welcome)
        layout.addWidget(self.text_chat)
        layout.addWidget(self.entry_message)
        layout.addWidget(self.button_send)
        layout.addWidget(self.entry_recipient)
        layout.addWidget(self.entry_private_message)
        layout.addWidget(self.button_send_private)
        layout.addWidget(self.text_notifications)
        layout.addLayout(bottom_layout)  # Ajout du layout inférieur avec le bouton "Quitter"

        self.setLayout(layout)
        self.show()


    def update_chat_display(self):
        # Vider le contenu actuel du chat
        self.text_chat.clear()
        # Afficher uniquement les messages du salon actuel
        if self.current_salon and self.current_salon in self.message_history:
            for message in self.message_history[self.current_salon]:
                self.text_chat.append(message)
    
        
    def send_private_message(self):
        """
        Envoie un message privé à un autre utilisateur.
        """           
        # Récupérer le destinataire et le message à partir des champs de saisie
        recipient_alias = self.entry_recipient.text() # Alias du destinataire du message privé
        message = self.entry_private_message.text()  # Utiliser le nouveau champ pour le message privé

        if recipient_alias and message:
            # Préparer les données à envoyer
            data = json.dumps({
                "action": "send_private_message", 
                "recipient": recipient_alias, 
                "message": message, 
                "alias": self.alias # Alias de l'expéditeur
            })
            # Envoyer les données au serveur
            self.client_socket.send(data.encode('utf-8'))
            # Effacer les champs après l'envoi
            self.entry_private_message.clear()


    def join_salon(self):
        """
        Rejoint un nouveau salon de chat sélectionné par l'utilisateur.

        Cette méthode vérifie si l'utilisateur est déjà dans un salon et,
        si ce n'est pas le cas, envoie une demande au serveur pour rejoindre le nouveau salon.
        Elle met également à jour l'affichage du chat pour le nouveau salon.
        """
        selected_salon = self.salon_selector.currentText()

        # Vérifier si l'utilisateur est déjà dans un salon
        if self.current_salon is not None and self.current_salon != selected_salon:
            QMessageBox.warning(self, "Action requise", "Vous devez quitter le salon actuel avant d'en rejoindre un nouveau.")
            return  # Ne pas continuer avec la demande de rejoindre le salon

        # Préparer les données pour rejoindre le nouveau salon et les envoyer au serveur
        data = json.dumps({"action": "request_join_salon", "salon_name": selected_salon, "alias": self.alias})
        self.client_socket.send(data.encode('utf-8'))

        # Mettre à jour le salon actuel de l'utilisateur
        self.current_salon = selected_salon
        self.update_chat_display()  # Mettre à jour l'affichage du chat pour le nouveau salon


    def leave_salon(self):
        """
        Quitte le salon de chat actuel.

        Envoie une demande au serveur pour quitter le salon actuel et met à jour l'interface utilisateur en conséquence.
        """
        if self.current_salon is None:
            # Informer l'utilisateur qu'il n'est dans aucun salon
            QMessageBox.information(self, "Information", "Vous n'êtes dans aucun salon à quitter.")
            return

        # Envoyer la demande de quitter le salon au serveur
        data = json.dumps({"action": "leave_salon", "salon_name": self.current_salon, "alias": self.alias})
        self.client_socket.send(data.encode('utf-8'))

        # Réinitialiser le salon actuel à None
        self.current_salon = None
        self.update_chat_display()  # Vider l'affichage du chat puisque vous avez quitté le salon

    def send_message(self):
        """
        Envoie un message au salon actuel.
        """
        if not self.current_salon:
            # Afficher une erreur si l'utilisateur a quitté le salon et tente d'envoyer un message
            QMessageBox.warning(self, "Action impossible", "Vous devez être dans un salon pour envoyer des messages.")
            return  # Ne pas continuer avec l'envoi du message

        message = self.entry_message.text()
        if message:  # S'assurer que le message n'est pas vide
            data = json.dumps({
                "action": "send_message",
                "message": message,
                "alias": self.alias,
                "salon": self.current_salon  # Ajouter le nom du salon au message
            })
            self.client_socket.send(data.encode('utf-8'))
            self.entry_message.clear()

    def display_message(self, message):
        """
        Affiche les messages reçus du serveur.

        Cette méthode gère l'affichage des messages normaux, des avertissements,
        et des notifications administratives. Elle gère aussi la fermeture
        de la session en cas de kick ou ban.

            message (str): Le message brut reçu du serveur.
        """
        try:
            # Tenter de convertir le message en JSON
            message_data = json.loads(message)

            # Gérer les messages d'administration spéciaux
            if message_data.get("type") == "warning":
                QMessageBox.warning(self, "Avertissement", message_data.get("content"))
                # Vous pouvez ajouter une logique supplémentaire ici, si nécessaire
                return  # Arrêter le traitement supplémentaire du message

            # Gérer d'autres types de messages spéciaux ici (ex. messages administratifs, etc.)

        except json.JSONDecodeError:
            # Si ce n'est pas un message JSON, continuez avec le traitement normal des messages
            pass  # ou logique pour gérer un message texte brut

        # Gère les messages d'administration spéciaux envoyés
        if message == "You have been kicked out!":
            QMessageBox.warning(self, "Kicked Out", "You have been kicked out by the admin.")
            self.client_socket.close()
            self.close()
            return
        elif message == "Server is shutting down!":
            QMessageBox.warning(self, "Server Shutdown", "The server is shutting down.")
            self.client_socket.close()
            self.close()
            return
        elif "You have been banned" in message:
            QMessageBox.warning(self, "Banned", message)
            self.client_socket.close()
            self.close()
            return

        # Définir une liste de mots-clés ou de phrases qui indiquent une notification
        notification_keywords = [
            "Ajouté au salon",
            "Authentification reçue pour le client",
            "Vous avez quitté le salon",
            "Demande envoyée pour rejoindre le salon",
            "Vous avez rejoint le salon",
            "Accès au salon",
            "Erreur lors de la tentative de quitter le salon",
            "Message ou salon non spécifié.",
            "Destinataire non trouvé.",
        ]

        # Vérifier si le message est une notification
        if any(keyword in message for keyword in notification_keywords):
            # Si le message est une notification, l'afficher dans text_notifications
            self.text_notifications.append(message)
        else:
            # Sinon, l'afficher dans text_chat
            self.text_chat.append(message)


    def change_salon(self, new_salon):
        # Change le salon actuel pour le nouvellement sélectionné
        self.current_salon = new_salon
        self.text_chat.clear()
        # Affiche l'historique des messages du nouveau salon
        if new_salon in self.message_history:
            for message in self.message_history[new_salon]:
                self.text_chat.append(message)  # Réafficher l'historique pour ce salon

    def quitter_application(self):
        try:
            # Envoyer une notification de déconnexion au serveur
            data = json.dumps({"action": "client_quit", "alias": self.alias})
            self.client_socket.send(data.encode('utf-8'))
        except Exception as e:
            print(f"Erreur lors de l'envoi de la notification de déconnexion : {e}")
        finally:
            # Fermer la socket et quitter l'application
            self.client_socket.close()
            self.close()
#######################################
############"Serveur"##############
#######################################
class ServerConnectionWindow(QWidget):
    """
    Fenêtre pour la connexion au serveur de l'application de chat.

    Permet à l'utilisateur d'entrer l'adresse et le port du serveur auquel se connecter,
    puis tente d'établir une connexion. En cas de succès, passe à l'interface d'authentification.
    """
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """
        Configure l'interface utilisateur de la fenêtre de connexion.
        """
        # Configurer la fenêtre
        self.setWindowTitle("Connexion au Serveur")
        self.setGeometry(300, 300, 300, 200)  # Positionnement et dimensionnement
        apply_stylesheet(self)

        # Création des widgets
        self.label_server_address = QLabel("Adresse du serveur:")
        self.edit_server_address = QLineEdit(self)
        self.edit_server_address.setPlaceholderText("Exemple : 127.0.0.1")

        self.label_server_port = QLabel("Port:")
        self.edit_server_port = QLineEdit(self)
        self.edit_server_port.setPlaceholderText("Exemple : 12345")

        self.button_connect = QPushButton('Connexion', self)
        self.button_connect.clicked.connect(self.on_connect_clicked)

        # Organisation des widgets dans le layout
        layout = QVBoxLayout()
        layout.addWidget(self.label_server_address)
        layout.addWidget(self.edit_server_address)
        layout.addWidget(self.label_server_port)
        layout.addWidget(self.edit_server_port)
        layout.addWidget(self.button_connect)

        self.setLayout(layout)

    def on_connect_clicked(self):
        """
        Gère l'événement de clic sur le bouton de connexion.

        Récupère l'adresse et le port du serveur à partir des champs de saisie,
        valide l'entrée, et tente de se connecter au serveur. En cas de succès,
        il ferme la fenêtre actuelle et ouvre la fenêtre d'authentification.
        """
        # Récupérer l'adresse et le port à partir des champs de saisie
        server_address = self.edit_server_address.text()
        server_port = self.edit_server_port.text()

        # Validation basique
        if not server_address or not server_port.isdigit():
            QMessageBox.warning(self, "Erreur", "Adresse ou port invalide.")
            return

        # Conversion du port en entier
        server_port = int(server_port)

        # Tentative de connexion au serveur
        try:
            # Création du socket et tentative de connexion
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_address, server_port))
            
            # Stocker l'adresse et le port pour utilisation ultérieure
            self.server_address = (server_address, server_port)
            
            # Si la connexion est réussie, informer l'utilisateur et ouvrir la fenêtre d'authentification
            QMessageBox.information(self, "Connexion Réussie", f"Connexion réussie à {server_address}:{server_port}")
            self.open_authentication_interface(self.client_socket)

        except Exception as e:  # Attrapez l'exception si la connexion échoue
            QMessageBox.critical(self, "Erreur de Connexion", f"Impossible de se connecter au serveur: {e}")
            return
    def open_authentication_interface(self, client_socket):
        """
        Ouvre l'interface d'authentification après une connexion réussie.
        """
        try:
            self.close()  # Ferme la fenêtre actuelle
            self.auth_window = ConnexionClient(client_socket, self.server_address)  # Passer le socket et l'adresse
            self.auth_window.show()  # Montre la nouvelle fenêtre
            self.auth_window.activateWindow()  # Optionnel: Mettez la fenêtre au premier plan
        except Exception as e:
            print("Erreur lors de l'ouverture de l'interface d'authentification:", e)


#######################################
############"Connexion"##############
#######################################
class ConnexionClient(QWidget):
    """
    Interface client pour la connexion et l'inscription au serveur de chat.

    Permet à l'utilisateur d'entrer son alias et son mot de passe pour se connecter,
    ou de naviguer vers la page d'inscription pour créer un nouveau compte.
    """
    def __init__(self, client_socket=None, server_address=None):
        super().__init__()
        self.client_socket = client_socket
        self.server_address = server_address  # Nouvel attribut pour stocker l'adresse du serveur
        self.init_ui()
        apply_stylesheet(self)

    def init_ui(self):
        self.setWindowTitle("Connexion au serveur")
        # Création des champs pour l'alias et le mot de passe
        self.label_alias = QLabel("Alias:")
        self.edit_alias = QLineEdit(self)
        

        self.label_password = QLabel("Mot de passe:")
        self.edit_password = QLineEdit(self)
        self.edit_password.setEchoMode(QLineEdit.Password)
        
        # Création des boutons de connexion et d'inscription
        self.btn_login = QPushButton("Se connecter", self)
        self.btn_signup = QPushButton("S'inscrire", self)
        
        # Connexion des signaux aux méthodes correspondantes
        self.btn_login.clicked.connect(self.login)
        self.btn_signup.clicked.connect(self.show_signup_page)
        
        # Organisation des boutons
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.btn_login)
        button_layout.addWidget(self.btn_signup)
        
        # Organisation des widgets
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.label_alias)
        main_layout.addWidget(self.edit_alias)
        main_layout.addWidget(self.label_password)
        main_layout.addWidget(self.edit_password)
        main_layout.addLayout(button_layout)
        
        # Applique le layout principal à la fenêtre
        self.setLayout(main_layout)

    def send_data(self, data):
        """
        Envoie des données au serveur et traite la réponse.
        """
        try:
            # Envoyer les données en utilisant le socket déjà connecté
            self.client_socket.sendall(json.dumps(data).encode("utf-8"))
            # Recevoir la réponse du serveur
            response = self.client_socket.recv(1024).decode("utf-8")
            self.process_data(response)
        except Exception as e:
            QMessageBox.critical(self, "Erreur Réseau", str(e))
            # Gérer plus spécifiquement l'exception ou fermer le socket si nécessaire


    def login(self):
        """
        Collecte les informations de connexion et envoie une demande de connexion au serveur.
        """
        # Récupérer les informations de connexion
        alias = self.edit_alias.text()
        password = self.edit_password.text()
        # Envoyer les informations au serveur pour verification
        data = {"action": "login", "alias": alias, "password": password}
        self.send_data(data)
    
    
    def show_signup_page(self):
        """
        Affiche la fenêtre d'inscription pour les nouveaux utilisateurs.
        """
        self.signup_page = InscriptionClient(self)
        self.signup_page.show()
        self.hide()


    def open_chat_interface(self):
        """
        Ouvre l'interface de chat après une connexion réussie.
        """
        self.alias = self.edit_alias.text()
        self.chat_window = ChatClient(self.alias, self.client_socket)
        self.chat_window.show()
        self.close()

    def process_data(self, response):
        """
        Traite la réponse du serveur après l'envoi de données.

        Selon la réponse du serveur, cette méthode affiche différents messages à l'utilisateur et,
        si la connexion est réussie, elle ouvre l'interface de chat.
        """
        if response == "Connexion réussie":
            QMessageBox.information(self, "Connexion réussie", "Connexion réussie !")
            self.open_chat_interface()
        elif response == "Alias ou mot de passe incorrect":
            QMessageBox.warning(self, "Échec de la connexion", "Alias ou mot de passe incorrect.")
        elif response == "Erreur de connexion à la base de données":
            QMessageBox.critical(self, "Erreur", "Erreur de connexion à la base de données.")
        elif response == "Inscription réussie":
            QMessageBox.information(self, "Inscription réussie", "Inscription réussie !")
        elif response == "Alias déjà utilisé":
            QMessageBox.warning(self, "Alias déjà utilisé", "Cet alias est déjà utilisé. Veuillez en choisir un autre.")
        else:
            print(f"Réponse non traitée du serveur : {response}")
#######################################
############"Inscription"##############
#######################################
class InscriptionClient(QWidget):
    """
    Interface client pour l'inscription à l'application de chat.

    Permet à l'utilisateur de créer un nouveau compte en entrant son nom, prénom,
    alias et mot de passe, puis envoie ces informations au serveur pour création.
    """
    def __init__(self, parent=None):
        super().__init__()
        apply_stylesheet(self)
        self.setWindowTitle("Inscription")
        self.setGeometry(300, 300, 300, 200)
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        """
        Configure et crée l'interface utilisateur pour l'inscription.
        """
        # Création des champs pour les informations de l'utilisateur
        self.label_nom = QLabel("Nom:")
        self.edit_nom = QLineEdit(self)

        self.label_prenom = QLabel("Prénom:")
        self.edit_prenom = QLineEdit(self)

        self.label_alias = QLabel("Alias:")
        self.edit_alias = QLineEdit(self)

        self.label_password = QLabel("Mot de passe:")
        self.edit_password = QLineEdit(self)
        self.edit_password.setEchoMode(QLineEdit.Password)

        self.btn_signup = QPushButton("S'inscrire", self)
        self.btn_signup.clicked.connect(self.signup)

        self.btn_retour = QPushButton("Retour", self)
        self.btn_retour.clicked.connect(self.show_login_page)

        # Création du bouton d'inscription et de retour
        layout = QVBoxLayout()
        layout.addWidget(self.label_nom)
        layout.addWidget(self.edit_nom)
        layout.addWidget(self.label_prenom)
        layout.addWidget(self.edit_prenom)
        layout.addWidget(self.label_alias)
        layout.addWidget(self.edit_alias)
        layout.addWidget(self.label_password)
        layout.addWidget(self.edit_password)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.btn_signup)
        button_layout.addWidget(self.btn_retour)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def signup(self):
        """
        Récupère les informations d'inscription et envoie une demande d'inscription au serveur.
        """
        # Récupérer les données d'inscription
        nom = self.edit_nom.text()
        prenom = self.edit_prenom.text()
        alias = self.edit_alias.text()
        password = self.edit_password.text()

        # Valider les champs
        if not nom or not prenom or not alias or not password:
            QMessageBox.warning(self, "Champs vides", "Veuillez remplir tous les champs.")
            return

        # Envoyer les données au serveur
        data = {"action": "signup", "nom": nom, "prenom": prenom, "alias": alias, "password": password}
        self.parent.send_data(data)

    def show_login_page(self):
        self.hide()
        self.parent.show()

def apply_stylesheet(widget):
    """
    Applique un style global à un widget PyQt.
    """
    # Style global pour l'application
    widget.setStyleSheet("""
    QWidget {
        background-color: #d3d3d3;  /* Light grey background */
    }
    QTextEdit, QLineEdit, QComboBox, QListWidget {
        border: 1px solid #ccc;
        font-family: Arial;
        font-size: 14px;
        background-color: #ffffff;  /* White background for text areas */
        color: #000000;  /* Black font color */
    }
    QPushButton {
        background-color: #0078d7;
        color: white;
        border-radius: 5px;
        padding: 10px 15px;
        margin: 5px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #005fa3;
    }
    """)

    # Appliquer le style spécifique pour le bouton "Quitter"
    if hasattr(widget, 'quitter_button'):
        widget.quitter_button.setStyleSheet("""
        QPushButton {
            background-color: #ff0000; /* Rouge */
            color: white;
            font-size: 12px; /* Taille du texte ajustée */
            border-radius: 5px;
            padding: 5px 10px;
            margin: 5px;
        }
        QPushButton:hover {
            background-color: #cc0000; /* Rouge plus sombre */
        }
        """)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ServerConnectionWindow()
    window.show()
    sys.exit(app.exec_())
