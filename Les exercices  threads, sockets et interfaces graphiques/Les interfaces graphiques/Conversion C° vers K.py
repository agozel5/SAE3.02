import sys

from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QComboBox, QLineEdit, QGridLayout, QMessageBox, QPushButton, QDialog, QVBoxLayout
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QDoubleValidator



class HelpDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Aide')
        self.resize(400,200)
        label = QLabel('Ce programme convertit la température entre Celsius et Kelvin.', self)
        layout = QVBoxLayout()
        layout.addWidget(label)
        self.setLayout(layout)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fermer)
        self.timer.start(2000)  # 2000 millisecondes = 2 secondes

    def fermer(self):
        self.timer.stop()  # Arrêtez le QTimer
        self.close() 


class TemperatureConverteur(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Convertisseur de Température')
        self.resize(400,250)

        self.label1 = QLabel('°C', self)
        self.label2 = QLabel('K', self)
        self.combo_unit = QComboBox(self)
        self.combo_unit.addItem('°C -> K')
        self.combo_unit.addItem('K -> °C')
        self.combo_unit.currentIndexChanged.connect(self.maj)

        self.label_temperature = QLabel('Température:', self)
        self.texte_temperature = QLineEdit(self)
        self.texte_temperature.setValidator(QDoubleValidator())

        self.label_conversion = QLabel('Conversion:', self)
        self.text_conversion = QLineEdit(self)
        self.text_conversion.setEnabled(False)

        self.convert_button = QPushButton('Convertir', self)
        self.convert_button.clicked.connect(self.convert_temperature)

        self.ne = QPushButton('?', self)
        self.ne.clicked.connect(self.aide)

        grid = QGridLayout()
        grid.addWidget(self.label1,0,2)
        grid.addWidget(self.combo_unit,1,2)
        grid.addWidget(self.label_temperature,0,0)
        grid.addWidget(self.texte_temperature,0,1)
        grid.addWidget(self.label_conversion,2,0)
        grid.addWidget(self.label2,2,2)
        grid.addWidget(self.convert_button,1,1)
        grid.addWidget(self.text_conversion,2,1)
        grid.addWidget(self.ne,3,4)
        
        self.setLayout(grid)

    def convert_temperature(self):
        try:
            temperature = float(self.texte_temperature.text())
            if self.combo_unit.currentText() == '°C -> K':
                upd_temp = temperature + 273.15
            else:
                upd_temp = temperature - 273.15

            self.text_conversion.setText(str(round(upd_temp, 2)))

        except ValueError:
            QMessageBox.warning(self, 'Erreur de saisie', 'Veuillez saisir une valeur numérique.')

    def maj(self, index):
        if index == 0:
            self.label1.setText('°C')
            self.label2.setText('K')
        else:
            self.label1.setText('K')
            self.label2.setText('°C')

    def aide(self):
        page = HelpDialog()
        page.exec()
        page.close()
if __name__ == '__main__':
    app = QApplication(sys.argv)
    converter = TemperatureConverteur()
    converter.show()
    sys.exit(app.exec())
