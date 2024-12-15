import base64
import os
import sys
from io import BytesIO

import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

API_URL = "http://127.0.0.1:8080/cr/api/"  # URL API

class FileTransferClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

        self.client_key = RSA.generate(1024)
        self.public_key = self.client_key.publickey().export_key().decode()
        self.symmetric_key = None
        self.username = None
        self.user_id = None

    def save_private_key(self, filename):
        """Сохранение приватного ключа в файл"""
        private_key = self.client_key.export_key()  # Экспорт приватного ключа
        with open(f'{filename}/{self.username}_private_key', 'wb') as f:
            f.write(private_key)

    def load_private_key(self, filename):
        """Загрузка приватного ключа из файла."""
        with open(f'{filename}/{self.username}_private_key', 'rb') as f:
            private_key = f.read()  # Чтение содержимого файла
        return RSA.import_key(private_key)

    def save_symmetric_key(self, filename: str):
        """
        Сохраняет симметричный ключ в файл в бинарном виде.
        """
        try:
            with open(f'{filename}/{self.username}_symmetric_key', "wb") as f:
                f.write(self.symmetric_key)
            self.log_message(f"[INFO] Симметричный ключ сохранен в {filename}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка сохранения симметричного ключа: {e}")

    def load_symmetric_key(self, filename: str):
        """
        Загружает симметричный ключ из файла.
        """
        try:
            with open(f'{filename}/{self.username}_symmetric_key', "rb") as f:
                self.symmetric_key = f.read()
            self.log_message(f"[INFO] Симметричный ключ успешно загружен из {filename}")
        except FileNotFoundError:
            self.log_message(f"[ERROR] Файл с симметричным ключом не найден: {filename}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка загрузки симметричного ключа: {e}")

    def init_ui(self):
        self.setWindowTitle("File Transfer Client")
        self.setGeometry(300, 300, 600, 400)

        # Основные элементы интерфейса
        main_layout = QVBoxLayout()

        self.username_label = QLabel("Имя пользователя:")

        button_layout = QHBoxLayout()

        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(self.register)

        # Кнопка для входа
        self.login_button = QPushButton("Вход")
        self.login_button.clicked.connect(self.login)

        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.register_button)

        self.username_display = QLabel()


        self.upload_button = QPushButton("Загрузить файл")
        self.upload_button.clicked.connect(self.upload_file)
        self.upload_button.setDisabled(True)

        self.list_button = QPushButton("Список файлов")
        self.list_button.clicked.connect(self.list_files)
        self.list_button.setDisabled(True)

        self.download_button = QPushButton("Скачать файл")
        self.download_button.clicked.connect(self.download_file)
        self.download_button.setDisabled(True)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        main_layout.addWidget(self.username_label)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.username_display)
        main_layout.addWidget(self.upload_button)
        main_layout.addWidget(self.list_button)
        main_layout.addWidget(self.download_button)
        main_layout.addWidget(QLabel("Логи:"))
        main_layout.addWidget(self.log)


        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def log_message(self, message):
        self.log.append(message)

    def handle_successful_login(self, username):
        """Обработчик успешного входа или регистрации."""
        # Скрыть кнопки и показать имя
        self.login_button.setVisible(False)
        self.register_button.setVisible(False)
        self.username_display.setVisible(True)
        self.username_display.setText(f"Добро пожаловать, {username}!")  # Отображаем имя пользователя


    def enable_buttons(self):
        """Разрешаем доступ к функционалу после успешного входа"""
        self.upload_button.setEnabled(True)
        self.list_button.setEnabled(True)
        self.download_button.setEnabled(True)

    def login(self):
        # Создаем диалоговое окно для входа
        dialog = QDialog(self)
        dialog.setWindowTitle("Вход")

        layout = QFormLayout()

        self.username_input_login = QLineEdit()
        self.password_input_login = QLineEdit()
        self.password_input_login.setEchoMode(QLineEdit.Password)

        layout.addRow("Имя пользователя:", self.username_input_login)
        layout.addRow("Пароль:", self.password_input_login)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(buttons)

        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.Accepted:
            username = self.username_input_login.text()
            password = self.password_input_login.text()

            data = {
            "username": username,
            "password": password,
            }
            try:
                response = requests.post(f"{API_URL}user/login/", json=data)
                if response.status_code == 200:
                    self.user_id = response.json().get("user_id")
                    self.username = username
                    self.load_private_key(filename=f'private_key/{self.user_id}')
                    self.load_symmetric_key(filename=f'private_key/{self.user_id}')

                    self.log_message("[INFO] Вход успешный! Симметричный ключ получен.")
                    self.log_message(f"[INFO] SK: {self.symmetric_key}")
                    self.enable_buttons()
                    dir_path = f'private_key/{self.user_id}'
                    os.makedirs(dir_path, exist_ok=True)

                    self.handle_successful_login(username)
                else:
                    self.log_message(f"[ERROR] Не удалось зарегистрироваться: {response.json()}")
            except Exception as e:
                self.log_message(f"[ERROR] Ошибка регистрации: {e}")

    def register(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Регистрация")

        layout = QFormLayout()

        self.username_input_register = QLineEdit()
        self.password_input_login = QLineEdit()
        self.password_input_login.setEchoMode(QLineEdit.Password)

        layout.addRow("Имя пользователя:", self.username_input_register)
        layout.addRow("Пароль:", self.password_input_login)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(buttons)

        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.Accepted:
            username = self.username_input_register.text().strip()
            password = self.password_input_login.text().strip()

        # username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Ошибка", "Имя пользователя не может быть пустым!")
            return

        if not password :
            QMessageBox.warning(self, "Ошибка", "Имя пользователя не может быть пустым!")
            return

        # Отправка открытого ключа на сервер
        data = {
            "username": username,
            "password": password,
            "public_key": self.public_key
        }
        try:
            response = requests.post(f"{API_URL}user/register/", json=data)
            if response.status_code == 201:
                self.symmetric_key = base64.b64decode(response.json().get("symmetric_key"))
                self.username = username
                self.user_id = response.json()['user_id']
                self.log_message("[INFO] Регистрация успешна! Симметричный ключ получен.")
                self.log_message(f"[INFO] SK: {self.symmetric_key}")
                self.enable_buttons()
                dir_path = f'private_key/{self.user_id}'
                os.makedirs(dir_path, exist_ok=True)
                self.save_private_key(filename=f'private_key/{self.user_id}')
                self.save_symmetric_key(filename=f'private_key/{self.user_id}')
                self.handle_successful_login(username)
            else:
                self.log_message(f"[ERROR] Не удалось зарегистрироваться: {response.json()}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка регистрации: {e}")


    def upload_file(self):
        if not self.symmetric_key:
            QMessageBox.warning(self, "Ошибка", "Вы не зарегистрированы!")
            return

        # Выбор файла для загрузки
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для загрузки")
        if not file_path:
            return

        file_name = file_path.split("/")[-1]
        try:
            rsa_cipher = PKCS1_OAEP.new(self.client_key.publickey())
            encrypted_symmetric_key = rsa_cipher.encrypt(self.symmetric_key)

            # Шифрование AES
            aes_cipher = AES.new(self.symmetric_key, AES.MODE_EAX)
            with open(file_path, 'rb') as f:
                file_data = f.read()

            ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)

            encrypted_file = BytesIO()
            # Сохраняем шифрованный симметрический ключ
            encrypted_file.write(len(encrypted_symmetric_key).to_bytes(2, 'big'))
            encrypted_file.write(encrypted_symmetric_key)
            # Сохраняем вектор инициализации и тег
            encrypted_file.write(aes_cipher.nonce)
            encrypted_file.write(tag)
            # Сохраняем зашифрованные данные
            encrypted_file.write(ciphertext)

            # Возвращаемся в начало потока для передачи
            encrypted_file.seek(0)

            params = {"user_id": self.user_id}
            files = {
                'file': (file_name, encrypted_file, 'application/octet-stream')
            }
            response = requests.post(f"{API_URL}user/upload/", params=params, files=files)

            if response.status_code == 201:
                self.log_message(f"[INFO] Файл {file_name} успешно загружен!")
            else:
                self.log_message(f"[ERROR] Не удалось загрузить файл: {response.json()}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка загрузки файла: {e}")

    def list_files(self):
        if not self.username:
            QMessageBox.warning(self, "Ошибка", "Вы не зарегистрированы!")
            return

        try:
            response = requests.get(f"{API_URL}files/get_file_list/{self.user_id}/")
            if response.status_code == 200:
                files = response.json()
                self.log_message(f"[INFO] Файлы на сервере: {', '.join([f['name'] for f in files])}")
            else:
                self.log_message(f"[ERROR] Не удалось получить список файлов: {response.json()}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка запроса списка файлов: {e}")

    def download_file(self):
        if not self.username:
            QMessageBox.warning(self, "Ошибка", "Вы не зарегистрированы!")
            return
        try:
            response = requests.get(f"{API_URL}files/get_file_list/{self.user_id}/")
            if response.status_code == 200:
                resp= response.json()
                files = [f['name'] for f in resp]
                if not files:
                    QMessageBox.information(self, "Информация", "Нет доступных файлов для скачивания.")
                    return
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось получить список файлов.")
                return
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка получения списка файлов: {e}")
            return

        # Диалог для выбора файла
        file_name, ok = QInputDialog.getItem(self, "Выбор файла", "Выберите файл для скачивания:", files, 0, False)
        if not ok or not file_name:
            return

        # Диалог для сохранения файла
        save_path, ok = QFileDialog.getSaveFileName(self, "Сохранить файл как")
        if not ok or not file_name:
            return

        try:
            response = requests.get(f"{API_URL}files/download_file/{self.user_id}/{file_name}/")
            if response.status_code == 200:
                data = response.json().get("data")
                binary_data = base64.b64decode(data)

                # Работаем с данными в памяти вместо временного файла
                data_stream = BytesIO(binary_data)

                # Читаем длину зашифрованного симметричного ключа
                encrypted_key_len = int.from_bytes(data_stream.read(2), 'big')

                # Читаем зашифрованный симметричный ключ
                encrypted_symmetric_key = data_stream.read(encrypted_key_len)

                # Расшифровываем симметричный ключ с помощью RSA
                rsa_cipher = PKCS1_OAEP.new(self.client_key)
                self.symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

                # Читаем nonce и tag
                nonce = data_stream.read(16)
                tag = data_stream.read(16)

                # Читаем зашифрованный текст
                ciphertext = data_stream.read()

                # Расшифровываем данные с помощью AES
                aes_cipher = AES.new(self.symmetric_key, AES.MODE_EAX, nonce=nonce)
                decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

                # Сохраняем расшифрованные данные в файл
                with open(f'{save_path}.{file_name.split(".")[-1]}', "wb") as f:
                    f.write(decrypted_data)
                self.log_message(f"[INFO] Файл {file_name} успешно скачан!")

            else:
                self.log_message(f"[ERROR] Не удалось скачать файл: {response.json()}")
        except Exception as e:
            self.log_message(f"[ERROR] Ошибка скачивания файла: {e}")

    def closeEvent(self, event):
        """Обработчик события закрытия окна."""
        reply = QMessageBox.question(self, 'Подтверждение',
                                     "Вы уверены, что хотите выйти?",
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        if reply == QMessageBox.Yes:
            # shutil.rmtree(f'tmp/')
            event.accept()  # Закрыть окно
        else:
            event.ignore()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileTransferClient()
    window.show()
    sys.exit(app.exec_())
