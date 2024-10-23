from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton, MDRectangleFlatButton
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.slider import MDSlider
from kivymd.uix.dialog import MDDialog
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivy.metrics import dp
import random
import string
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256

password_file = "passwords.ivli"
rockyou_path = "rockyou.txt"  # Put rockyou.txt in the same directory
rockyou_passwords = set()


# Функция для загрузки rockyou.txt
def load_rockyou():
    global rockyou_passwords
    if os.path.exists(rockyou_path):
        with open(rockyou_path, 'r', encoding='latin1') as f:
            rockyou_passwords = set(line.strip() for line in f)
    else:
        print("Warning: rockyou.txt not found. Leak check will not work.")

    # Генерация случайного пароля


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


# Проверка сложности пароля
def check_password_strength(password):
    length = len(password) >= 8
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    return "Strong" if all([length, has_upper, has_lower, has_digit, has_special]) else "Weak"


# Проверка утечки пароля
def check_leaked_password(password):
    return password in rockyou_passwords


class GenerateScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.password_input = MDTextField(hint_text="Generated Password", readonly=True, mode="rectangle")
        self.strength_value = MDLabel(text="", halign="center")
        self.leak_check_value = MDLabel(text="", halign="center")
        self.length_slider = MDSlider(min=8, max=32, value=12, step=1)
        self.length_slider.bind(value=self.on_slider_value_change)
        self.service_input = MDTextField(hint_text="Enter service name", mode="rectangle")
        self.email_input = MDTextField(hint_text="Enter email for this service", mode="rectangle")
        save_button = MDRaisedButton(text="Save Password", md_bg_color=self.app.theme_cls.primary_color)
        save_button.bind(on_press=self.on_save_password)
        generate_button = MDRaisedButton(text="Generate Password", md_bg_color=self.app.theme_cls.primary_color)
        generate_button.bind(on_press=self.on_generate_password)

        widgets = [self.password_input, self.strength_value, self.leak_check_value, self.length_slider,
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
        self.strength_value.text = f"Strength: {check_password_strength(password)}"
        leaked = check_leaked_password(password)
        self.leak_check_value.text = "Leaked!" if leaked else "Not Leaked"

    def on_save_password(self, instance):
        service = self.service_input.text
        password = self.password_input.text
        email = self.email_input.text if self.email_input.text else "N/A"  # Опциональный email, используем "N/A" если не введен
        if service and password:
            self.app.save_password(service, password, email)
            self.service_input.text = ""
            self.email_input.text = ""
            self.password_input.text = ""


class SavedScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation="vertical", padding=dp(10), spacing=dp(10))
        self.search_input = MDTextField(hint_text="Search by service name", mode="rectangle")
        self.search_input.bind(on_text_validate=self.on_search_password)  # Search on Enter press
        search_button = MDRaisedButton(text="Search", md_bg_color=self.app.theme_cls.primary_color)
        search_button.bind(on_press=self.on_search_password)

        self.saved_passwords = MDScrollView()
        self.passwords_list = MDLabel(text="", halign="left", valign="top")
        self.saved_passwords.add_widget(self.passwords_list)

        layout.add_widget(self.search_input)
        layout.add_widget(search_button)
        layout.add_widget(self.saved_passwords)
        self.add_widget(layout)

    def on_enter(self):
        self.app.load_saved_passwords()
        self.passwords_list.text = self.app.passwords_list_text

    def on_search_password(self, instance=None):
        service_name = self.search_input.text
        if service_name:
            self.app.search_password_by_service(service_name)


class CheckScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.check_password_input = MDTextField(hint_text="Enter password to check", password=True, mode="rectangle")
        self.check_password_input.bind(on_text_validate=self.on_check_password)  # Bind Enter key to check password
        check_button = MDRaisedButton(text="Check Password", md_bg_color=self.app.theme_cls.primary_color)
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
            self.check_strength_value.text = f"Strength: {check_password_strength(password)}"
            leaked = check_leaked_password(password)
            self.check_leak_check_value.text = "Leaked!" if leaked else "Not Leaked"


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
        self.title = "Password Manager"

        # Screen Manager
        self.sm = ScreenManager()

        # Adding screens with app instance
        self.sm.add_widget(GenerateScreen(app=self, name='generate'))
        self.sm.add_widget(SavedScreen(app=self, name='saved'))
        self.sm.add_widget(CheckScreen(app=self, name='check'))

        # Navigation Bar
        self.nav_bar = MDBottomNavigation(panel_color=self.theme_cls.bg_darkest)
        self.generate_item = MDBottomNavigationItem(
            name='generate', text='Generate', icon='key-plus', on_tab_press=self.switch_to_generate
        )
        self.saved_item = MDBottomNavigationItem(
            name='saved', text='Saved', icon='content-save', on_tab_press=self.switch_to_saved
        )
        self.check_item = MDBottomNavigationItem(
            name='check', text='Check', icon='shield-check', on_tab_press=self.switch_to_check
        )

        self.nav_bar.add_widget(self.generate_item)
        self.nav_bar.add_widget(self.saved_item)
        self.nav_bar.add_widget(self.check_item)

        self.root = MDBoxLayout(orientation='vertical')
        self.root.add_widget(self.sm)
        self.root.add_widget(self.nav_bar)

        load_rockyou()
        self.load_master_password()
        return self.root

    def switch_to_generate(self, instance):
        self.sm.current = 'generate'

    def switch_to_saved(self, instance):
        self.sm.current = 'saved'

    def switch_to_check(self, instance):
        self.sm.current = 'check'

    def derive_key(self, master_password=None):
        key = sha256(master_password.encode()).digest()
        key_b64 = base64.urlsafe_b64encode(key)
        return key_b64

    def save_password(self, service, password, email):
        if self.cipher:
            encrypted_data = self.cipher.encrypt(f"{service}:{password}:{email}".encode())
            with open(password_file, "ab") as f:
                f.write(encrypted_data + b"\n")
            self.load_saved_passwords()

    def load_saved_passwords(self):
        self.passwords_list_text = ""
        if os.path.exists(password_file):
            self.cipher = Fernet(self.derive_key(self.master_password))  # Re-create the cipher each time
            with open(password_file, "rb") as f:
                for line in f:
                    try:
                        decrypted_data = self.cipher.decrypt(line.strip())
                        service, password, email = decrypted_data.decode().split(":")
                        self.passwords_list_text += f"Service: {service} | Password: {password} | Email: {email}\n"
                    except InvalidToken:
                        self.passwords_list_text += "[ERROR] Invalid token. Could not decrypt password.\n"

    def search_password_by_service(self, service_name):
        if os.path.exists(password_file):
            self.cipher = Fernet(self.derive_key(self.master_password))  # Create a cipher using the master password
            result_text = ""
            with open(password_file, "rb") as f:
                for line in f:
                    try:
                        decrypted_data = self.cipher.decrypt(line.strip())
                        service, password, email = decrypted_data.decode().split(":")
                        if service.lower() == service_name.lower():
                            result_text += f"Service: {service} | Password: {password} | Email: {email}\n"
                    except InvalidToken:
                        result_text += "[ERROR] Invalid token. Could not decrypt password.\n"

            if result_text:
                self.sm.get_screen('saved').passwords_list.text = result_text
            else:
                self.sm.get_screen('saved').passwords_list.text = f"No passwords found for service: {service_name}"

    def load_master_password(self):
        master_password_file = "master_password.txt"
        if os.path.exists(master_password_file):
            with open(master_password_file, "r") as f:
                self.master_password = f.read().strip()
            self.cipher = Fernet(self.derive_key(self.master_password))
        else:
            self.show_error_dialog("Master password file not found!")

    def show_error_dialog(self, error_message):
        if not self.dialog:
            self.dialog = MDDialog(
                title="Error",
                text=error_message,
                buttons=[MDRectangleFlatButton(text="Close", on_release=self.close_dialog)]
            )
        self.dialog.text = error_message
        self.dialog.open()

    def close_dialog(self, instance):
        self.dialog.dismiss()


if __name__ == '__main__':
    PasswordManagerApp().run()