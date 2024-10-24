from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.slider import MDSlider
from kivymd.uix.dialog import MDDialog
from kivymd.uix.card import MDCard
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivymd.uix.button import MDIconButton
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivy.metrics import dp
from kivy.core.clipboard import Clipboard

import random
import string
import os

import base64
from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256, pbkdf2_hmac




password_file = "passwords.ivli"
master_password_file = "master_password.json"  # File to store the hashed master password
rockyou_path = "rockyou.txt"  # Place rockyou.txt in the same directory
rockyou_passwords = set()

Window.size = (600, 600)  # Фиксированный размер окна
Window.resizable = False  # Отключение возможности изменения размера

# Load rockyou.txt for password leak checks
def load_rockyou():
    global rockyou_passwords
    if os.path.exists(rockyou_path):
        with open(rockyou_path, 'r', encoding='latin1') as f:
            rockyou_passwords = set(line.strip() for line in f)
    else:
        print("Warning: rockyou.txt not found. Leak check will not work.")

# Generate a random password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Check password strength
def check_password_strength(password):
    length = len(password) >= 8
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    return "Strong" if all([length, has_upper, has_lower, has_digit, has_special]) else "Weak"

# Check if the password has been leaked
def check_leaked_password(password):
    return password in rockyou_passwords

# Function to hash the master password
def hash_password(password):
    salt = os.urandom(16)  # Generate a new salt
    hashed = pbkdf2_hmac('sha256', password.encode(), salt, 100000)  # Hash the password
    return base64.urlsafe_b64encode(salt + hashed).decode()  # Store salt and hash together

# Function to verify the hashed password
def verify_password(stored_password, provided_password):
    decoded = base64.urlsafe_b64decode(stored_password.encode())
    salt = decoded[:16]  # Extract the salt
    stored_hash = decoded[16:]  # Extract the hash
    new_hash = pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return new_hash == stored_hash  # Check if the hashes match

class MasterPasswordScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.password_input = MDTextField(hint_text="Введите мастер-пароль", password=True, mode="rectangle")

        submit_button = MDRaisedButton(text="Подтвердить", md_bg_color=self.app.theme_cls.primary_color)
        submit_button.bind(on_press=self.on_submit)

        layout.add_widget(self.password_input)
        layout.add_widget(submit_button)
        self.add_widget(layout)

    def on_submit(self, instance):
        master_password = self.password_input.text
        if master_password:
            self.app.set_master_password(master_password)

class MainAppScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(5), spacing=dp(5))

        # Creating screen manager for main functions
        self.sm = ScreenManager()
        self.sm.add_widget(GenerateScreen(app=self.app, name='generate'))
        self.sm.add_widget(SavedScreen(app=self.app, name='saved'))
        self.sm.add_widget(CheckScreen(app=self.app, name='check'))

        # Navigation panel
        self.nav_bar = MDBottomNavigation(panel_color=self.app.theme_cls.bg_darkest)
        self.generate_item = MDBottomNavigationItem(
            name='generate', text='Генерация', icon='key-plus', on_tab_press=self.switch_to_generate
        )
        self.saved_item = MDBottomNavigationItem(
            name='saved', text='Сохраненные', icon='content-save', on_tab_press=self.switch_to_saved
        )
        self.check_item = MDBottomNavigationItem(
            name='check', text='Проверка', icon='shield-lock', on_tab_press=self.switch_to_check
        )
        self.nav_bar.add_widget(self.generate_item)
        self.nav_bar.add_widget(self.saved_item)
        self.nav_bar.add_widget(self.check_item)

        layout.add_widget(self.sm)
        layout.add_widget(self.nav_bar)

        self.add_widget(layout)

    def switch_to_generate(self, instance):
        self.sm.current = 'generate'

    def switch_to_saved(self, instance):
        self.sm.current = 'saved'

    def switch_to_check(self, instance):
        self.sm.current = 'check'

class GenerateScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(5), spacing=dp(5))

        self.password_input = MDTextField(hint_text="Сгенерированный пароль", readonly=True, mode="rectangle")
        self.strength_value = MDLabel(text="", halign="center")
        self.leak_check_value = MDLabel(text="", halign="center")
        self.length_slider = MDSlider(min=8, max=32, value=12, step=1)
        self.length_slider.bind(value=self.on_slider_value_change)
        self.service_input = MDTextField(hint_text="Введите название сервиса", mode="rectangle")
        self.email_input = MDTextField(hint_text="Введите email для этого сервиса", mode="rectangle")

        save_button = MDRaisedButton(text="Сохранить пароль", md_bg_color=self.app.theme_cls.primary_color)
        save_button.bind(on_press=self.on_save_password)
        generate_button = MDRaisedButton(text="Сгенерировать пароль", md_bg_color=self.app.theme_cls.primary_color)
        generate_button.bind(on_press=self.on_generate_password)

        widgets = [self.password_input, self.length_slider,
                   self.service_input, self.email_input, save_button, generate_button]
        for widget in widgets:
            layout.add_widget(widget)

        self.add_widget(layout)

    def on_slider_value_change(self, instance, value):
        pass

    def on_generate_password(self, instance):
        length = int(self.length_slider.value)
        password = generate_password(length)
        self.password_input.text = password
        self.strength_value.text = f"Сложность: {check_password_strength(password)}"
        leaked = check_leaked_password(password)
        self.leak_check_value.text = "Утек!" if leaked else "Не утек"

    def on_save_password(self, instance):
        service = self.service_input.text
        password = self.password_input.text
        email = self.email_input.text if self.email_input.text else "N/A"  # Optional email
        if service and password:
            self.app.save_password(service, password, email)
            self.service_input.text = ""
            self.email_input.text = ""
            self.password_input.text = ""

class SavedScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation="vertical", padding=dp(5), spacing=dp(5))
        self.search_input = MDTextField(hint_text="Поиск по названию сервиса", mode="rectangle")
        self.search_input.bind(on_text_validate=self.on_search_password)  # Search on Enter
        search_button = MDRaisedButton(text="Поиск", md_bg_color=self.app.theme_cls.primary_color)
        search_button.bind(on_press=self.on_search_password)

        self.saved_passwords = MDScrollView()
        self.passwords_layout = MDBoxLayout(orientation='vertical', spacing=dp(10), size_hint_y=None)
        self.passwords_layout.bind(minimum_height=self.passwords_layout.setter('height'))
        self.saved_passwords.add_widget(self.passwords_layout)

        layout.add_widget(self.search_input)
        layout.add_widget(search_button)
        layout.add_widget(self.saved_passwords)
        self.add_widget(layout)

        self.context_dialog = None  # Store the context dialog here

    def on_enter(self):
        self.app.load_saved_passwords()
        self.populate_passwords()

    def populate_passwords(self):
        self.passwords_layout.clear_widgets()  # Clear previous entries
        for line in self.app.passwords_list_text.splitlines():
            if line.strip():
                parts = line.split("|")
                if len(parts) == 3:  # Ensure there are exactly 3 parts
                    service, email, password = parts
                    self.add_password_entry(service, email, password)
                else:
                    print(f"Skipping invalid line: {line}")

    def add_password_entry(self, service, email, password):
        card = MDCard(size_hint_y=None, height=dp(80))
        card_box = MDBoxLayout(orientation='horizontal', padding=dp(10), spacing=dp(10))

        password_label = MDLabel(text="*" * len(password), halign="left", theme_text_color="Custom",
                                 text_color=(1, 1, 1, 1))
        email_label = MDLabel(text=email, halign="left", theme_text_color="Custom", text_color=(1, 1, 1, 1))

        # Use MDIconButton with transparency
        eye_icon = MDIconButton(icon="eye-outline", size_hint_x=None, width=dp(30), md_bg_color=(0, 0, 0, 0))
        eye_icon.bind(on_press=lambda x: self.toggle_password_visibility(password_label, password, eye_icon))

        # Bind right-click action
        card.bind(on_touch_down=lambda card, touch: self.show_context_menu(touch, service, email, password))

        card_box.add_widget(MDLabel(text=f"Сервис: {service}", halign="left"))
        card_box.add_widget(email_label)
        card_box.add_widget(password_label)
        card_box.add_widget(eye_icon)

        card.add_widget(card_box)
        self.passwords_layout.add_widget(card)

    def toggle_password_visibility(self, password_label, password, eye_icon):
        if password_label.text == "*" * len(password):
            password_label.text = password  # Show password
            eye_icon.icon = "eye-off-outline"  # Change eye icon to closed
        else:
            password_label.text = "*" * len(password)  # Hide password
            eye_icon.icon = "eye-outline"  # Change eye icon to open

    def show_context_menu(self, touch, service, email, password):
        if touch.button == 'right':  # Check for right mouse button
            self.context_dialog = MDDialog(
                title="Выбор действия",
                text=f"Сервис: {service}\nEmail: {email}",
                buttons=[
                    MDRaisedButton(
                        text="Копировать пароль",
                        on_release=lambda x: [self.copy_to_clipboard(password), self.context_dialog.dismiss()]
                    ),
                    MDRaisedButton(
                        text="Копировать почту",
                        on_release=lambda x: [self.copy_to_clipboard(email), self.context_dialog.dismiss()]
                    ),
                    MDRaisedButton(
                        text="Отмена",
                        on_release=lambda x: self.context_dialog.dismiss()
                    ),
                ],
            )
            self.context_dialog.open()

    def copy_to_clipboard(self, text):
        Clipboard.copy(text)  # Use the clipboard module to copy the text

    def on_search_password(self, instance=None):
        service_name = self.search_input.text
        if service_name:
            self.app.search_password_by_service(service_name)
            self.populate_passwords()


class CheckScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(5), spacing=dp(5))
        self.check_password_input = MDTextField(hint_text="Введите пароль для проверки", password=True,
                                                mode="rectangle")
        self.check_password_input.bind(
            on_text_validate=self.on_check_password)  # Bind Enter key for password check
        check_button = MDRaisedButton(text="Проверить пароль", md_bg_color=self.app.theme_cls.primary_color)
        check_button.bind(on_press=self.on_check_password)
        self.check_strength_value = MDLabel(text="", halign="center")
        self.check_leak_check_value = MDLabel(text="", halign="center")

        layout.add_widget(self.check_password_input)
        layout.add_widget(check_button)
        layout.add_widget(self.check_strength_value)
        layout.add_widget(self.check_leak_check_value)
        self.add_widget(layout)

    def on_check_password(self, instance=None):
        password = self.check_password_input.text
        if password:
            self.check_strength_value.text = f"Сложность: {check_password_strength(password)}"
            leaked = check_leaked_password(password)
            self.check_leak_check_value.text = "Утек!" if leaked else "Не утек"

class PasswordManagerApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.master_password = None
        self.cipher = None
        self.dialog = None
        self.passwords_list_text = ""

    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        self.title = "Менеджер Паролей"

        # Screen manager
        self.sm = ScreenManager()
        self.sm.add_widget(MasterPasswordScreen(app=self, name='master_password'))
        self.sm.add_widget(MainAppScreen(app=self, name='main_app'))

        return self.sm

    def set_master_password(self, master_password):
        if not self.is_master_password_set():
            hashed_password = hash_password(master_password)
            with open(master_password_file, 'w') as f:
                f.write(hashed_password)  # Store hashed password
            self.master_password = master_password
            self.cipher = Fernet(self.derive_key(master_password))  # Initialize cipher here
            self.load_saved_passwords()  # Load passwords after setting master password
            self.sm.current = 'main_app'  # Switch to main screen after setting password
        else:
            with open(master_password_file, 'r') as f:
                stored_password = f.read()
                if verify_password(stored_password, master_password):
                    self.master_password = master_password
                    self.cipher = Fernet(self.derive_key(master_password))
                    self.load_saved_passwords()
                    self.sm.current = 'main_app'  # Switch to main screen if password is correct
                else:
                    self.dialog = MDDialog(text="Неверный мастер-пароль!", size_hint=(0.8, 1))
                    self.dialog.open()

    def is_master_password_set(self):
        return os.path.exists(master_password_file)

    def save_password(self, service, password, email):
        if self.cipher is None:  # Ensure cipher is initialized
            return

        encrypted_data = self.cipher.encrypt(f"{service}|{email}|{password}".encode())

        with open(password_file, "ab") as f:
            f.write(encrypted_data + b'\n')

    def load_saved_passwords(self):
        if self.cipher is None:  # Check if cipher is initialized
            return

        if os.path.exists(password_file):
            self.passwords_list_text = ""
            with open(password_file, "rb") as f:
                for line in f:
                    try:
                        decrypted_data = self.cipher.decrypt(line.strip()).decode()
                        self.passwords_list_text += decrypted_data + "\n"
                    except InvalidToken:
                        continue

    def search_password_by_service(self, service_name):
        results = []
        for line in self.passwords_list_text.splitlines():
            if service_name.lower() in line.lower():
                results.append(line)
        self.saved_passwords_list.text = "\n".join(results) if results else "Нет результатов."

    def on_start(self):
        self.sm.current = 'master_password'  # Show screen for entering master password

    def derive_key(self, password):
        return base64.urlsafe_b64encode(sha256(password.encode()).digest())

if __name__ == "__main__":
    load_rockyou()  # Load leaked passwords at startup
    PasswordManagerApp().run()