from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton, MDRectangleFlatButton
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.dialog import MDDialog
from kivymd.uix.navigationdrawer import MDNavigationDrawer
from kivymd.uix.list import OneLineListItem
from kivy.lang import Builder
from kivy.metrics import dp
import os
import random
import string
import base64
from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256

# UI Layout in KV language
KV = '''
MDNavigationLayout:
    ScreenManager:
        GenerateScreen:
            name: "generate"
        SavedScreen:
            name: "saved"
        CheckScreen:
            name: "check"

    MDNavigationDrawer:
        id: nav_drawer
        BoxLayout:
            orientation: 'vertical'
            MDList:
                OneLineListItem:
                    text: "Generate Password"
                    on_press:
                        nav_drawer.set_state("close")
                        app.root.current = "generate"
                OneLineListItem:
                    text: "Saved Passwords"
                    on_press:
                        nav_drawer.set_state("close")
                        app.root.current = "saved"
                OneLineListItem:
                    text: "Check Password"
                    on_press:
                        nav_drawer.set_state("close")
                        app.root.current = "check"

<GenerateScreen>:
    name: 'generate'
    MDBoxLayout:
        orientation: 'vertical'
        padding: dp(10)
        spacing: dp(10)
        MDTextField:
            id: password_input
            hint_text: "Generated Password"
            readonly: True
        MDLabel:
            id: strength_label
            text: "Strength: "
        MDLabel:
            id: leak_label
            text: "Leaked: "
        MDRaisedButton:
            text: "Generate Password"
            on_press: app.generate_password()
        MDRaisedButton:
            text: "Save Password"
            on_press: app.save_password()

<SavedScreen>:
    name: 'saved'
    MDBoxLayout:
        orientation: 'vertical'
        MDScrollView:
            MDLabel:
                id: saved_passwords_label
                text: "Saved Passwords will be displayed here."
                size_hint_y: None
                height: self.texture_size[1]

<CheckScreen>:
    name: 'check'
    MDBoxLayout:
        orientation: 'vertical'
        MDTextField:
            id: check_password_input
            hint_text: "Enter password to check"
            password: True
        MDRaisedButton:
            text: "Check Password"
            on_press: app.check_password()
        MDLabel:
            id: check_strength_label
            text: ""
        MDLabel:
            id: check_leak_label
            text: ""
'''

class GenerateScreen(Screen):
    pass

class SavedScreen(Screen):
    pass

class CheckScreen(Screen):
    pass

class PasswordManagerApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.master_password = None
        self.cipher = None
        self.passwords = {}  # Store passwords as a dictionary
        self.password_file = "passwords.ivli"
        self.rockyou_path = "rockyou.txt"  # Ensure rockyou.txt is in the same directory
        self.rockyou_passwords = set()
        self.load_rockyou()

    def build(self):
        return Builder.load_string(KV)

    def load_rockyou(self):
        if os.path.exists(self.rockyou_path):
            with open(self.rockyou_path, 'r', encoding='latin1') as f:
                self.rockyou_passwords = set(line.strip() for line in f)
        else:
            print("Warning: rockyou.txt not found. Leak check will not work.")

    def generate_password(self):
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        self.root.get_screen('generate').ids.password_input.text = password
        strength = self.check_password_strength(password)
        self.root.get_screen('generate').ids.strength_label.text = f"Strength: {strength}"
        leaked = self.check_leaked_password(password)
        self.root.get_screen('generate').ids.leak_label.text = "Leaked!" if leaked else "Not Leaked"

    def save_password(self):
        service = self.root.get_screen('generate').ids.password_input.text
        email = "N/A"  # Optional email, set to "N/A" if not entered
        if service:
            self.passwords[service] = self.root.get_screen('generate').ids.password_input.text
            self.update_saved_passwords()
            self.save_to_file(service, self.passwords[service], email)

    def update_saved_passwords(self):
        saved_passwords_label = self.root.get_screen('saved').ids.saved_passwords_label
        saved_passwords_text = "\n".join([f"{service}: {password}" for service, password in self.passwords.items()])
        saved_passwords_label.text = saved_passwords_text if saved_passwords_text else "No saved passwords."

    def check_password_strength(self, password):
        length = len(password) >= 8
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        return "Strong" if all([length, has_upper, has_lower, has_digit, has_special]) else "Weak"

    def check_leaked_password(self, password):
        return password in self.rockyou_passwords

    def check_password(self):
        password = self.root.get_screen('check').ids.check_password_input.text
        if password:
            strength = self.check_password_strength(password)
            leaked = self.check_leaked_password(password)
            self.root.get_screen('check').ids.check_strength_label.text = f"Strength: {strength}"
            self.root.get_screen('check').ids.check_leak_label.text = "Leaked!" if leaked else "Not Leaked"

    def save_to_file(self, service, password, email):
        if not os.path.exists(self.password_file):
            with open(self.password_file, "w") as f:
                pass  # Create the file if it doesn't exist
        with open(self.password_file, "a") as f:
            f.write(f"{service}:{password}:{email}\n")  # Save in the format "service:password:email"

if __name__ == "__main__":
    PasswordManagerApp().run()
