import sys
from PyQt5.QtWidgets import QLabel, QApplication, QVBoxLayout, QWidget, QPushButton, QCheckBox, QLineEdit

class Fenetre():
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.grid = QVBoxLayout()
        self.root = QWidget()
        self.root.setLayout(self.grid)
        self.root.resize(300, 100)
        self.root.setWindowTitle("Ma première fenêtre")

        self.ok_label = QLabel("Saisir votre nom")
        self.text = QLineEdit("")
        self.btn = QPushButton("OK")
        self.ne_label = QLabel("")
        self.btn2 = QPushButton("Quitter")
        self.box = QCheckBox("maj")

        self.grid.addWidget(self.ok_label)
        self.grid.addWidget(self.text)
        self.grid.addWidget(self.btn)
        self.grid.addWidget(self.ne_label)
        self.grid.addWidget(self.btn2)

        self.btn.clicked.connect(self.update_ne_label) 
        self.btn2.clicked.connect(self.quitter)

        self.root.show()

        sys.exit(self.app.exec())

    def update_ne_label(self):
        prenom = self.text.text()
        self.ne_label.setText(f"Bonjour {prenom}")

    def quitter(self):
        self.app.quit()

if __name__ == '__main__':
    fenetre = Fenetre()
