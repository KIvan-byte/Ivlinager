from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.label import MDLabel
from kivymd.uix.slider import MDSlider
from kivymd.uix.scrollview import MDScrollView
from kivy.metrics import dp
import os
from kivymd.uix.card import MDCard  # <-- Добавлен импорт для MDCard
import random
import string


password_file = "passwords.ivli"
rockyou_path = "rockyou.txt"
rockyou_passwords = set()


def load_rockyou():
    global rockyou_passwords
    if os.path.exists(rockyou_path):
        with open(rockyou_path, 'r', encoding='latin1') as f:
            rockyou_passwords = set(line.strip() for line in f)
    else:
        print("Warning: rockyou.txt not found. Leak check will not work.")


def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def check_password_strength(password):
    length = len(password) >= 8
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    return "Strong" if all([length, has_upper, has_lower, has_digit, has_special]) else "Weak"


def check_leaked_password(password):
    return password in rockyou_passwords


class GenerateScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.password_input = MDTextField(hint_text="Generated Password", readonly=True, mode="rectangle")
        self.length_slider = MDSlider(min=8, max=32, value=12, step=1)
        self.service_input = MDTextField(hint_text="Enter service name", mode="rectangle")
        self.email_input = MDTextField(hint_text="Enter email for this service", mode="rectangle")
        save_button = MDRaisedButton(text="Save Password", md_bg_color=self.app.theme_cls.primary_color)
        save_button.bind(on_press=self.on_save_password)
        generate_button = MDRaisedButton(text="Generate Password", md_bg_color=self.app.theme_cls.primary_color)
        generate_button.bind(on_press=self.on_generate_password)

        widgets = [self.password_input, self.length_slider, self.service_input, self.email_input, save_button, generate_button]
        for widget in widgets:
            layout.add_widget(widget)

        self.add_widget(layout)

    def on_generate_password(self, instance):
        length = int(self.length_slider.value)
        password = generate_password(length)
        self.password_input.text = password

    def on_save_password(self, instance):
        service = self.service_input.text
        password = self.password_input.text
        email = self.email_input.text if self.email_input.text else "N/A"
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

        # Search section
        self.search_input = MDTextField(hint_text="Search by service name", mode="rectangle")
        self.search_input.bind(on_text_validate=self.on_search_password)
        search_button = MDRaisedButton(text="Search", md_bg_color=self.app.theme_cls.primary_color)
        search_button.bind(on_press=self.on_search_password)

        # Scrollable area for saved passwords
        self.saved_passwords = MDScrollView()
        self.passwords_list = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.saved_passwords.add_widget(self.passwords_list)

        layout.add_widget(self.search_input)
        layout.add_widget(search_button)
        layout.add_widget(self.saved_passwords)
        self.add_widget(layout)

    def on_enter(self):
        self.app.load_saved_passwords()
        self.populate_passwords(self.app.passwords_list_text)

    def on_search_password(self, instance=None):
        service_name = self.search_input.text
        if service_name:
            self.app.search_password_by_service(service_name)

    def populate_passwords(self, passwords_text):
        # Clear previous widgets
        self.passwords_list.clear_widgets()

        for line in passwords_text.strip().split("\n"):
            if line:
                card = MDCard(orientation="vertical", padding=dp(10), size_hint=(1, None), height=dp(100))
                details = line.split("|")
                service = details[0].split(": ")[1].strip()
                password = details[1].split(": ")[1].strip()
                email = details[2].split(": ")[1].strip()

                card.add_widget(MDLabel(text=f"Service: {service}"))
                card.add_widget(MDLabel(text=f"Password: {password}"))
                card.add_widget(MDLabel(text=f"Email: {email}"))

                self.passwords_list.add_widget(card)


class CheckScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        layout = MDBoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        self.check_password_input = MDTextField(hint_text="Enter password to check", password=True, mode="rectangle")
        check_button = MDRaisedButton(text="Check Password", md_bg_color=self.app.theme_cls.primary_color)
        check_button.bind(on_press=self.on_check_password)

        layout.add_widget(self.check_password_input)
        layout.add_widget(check_button)
        self.add_widget(layout)

    def on_check_password(self, instance=None):
        password = self.check_password_input.text
        if password:
            print(f"Checking password: {password}")
            # Логика проверки пароля (например, сила пароля)


class PasswordManagerApp(MDApp):
    def build(self):
        self.sm = ScreenManager()
        self.sm.add_widget(GenerateScreen(name='generate', app=self))
        self.sm.add_widget(SavedScreen(name='saved', app=self))
        self.sm.add_widget(CheckScreen(name='check', app=self))

        layout = MDBoxLayout(orientation='vertical')

        # Нижняя панель навигации с кастомными кнопками
        bottom_nav_bar = MDBoxLayout(size_hint_y=None, height=dp(56), spacing=dp(10), padding=dp(10))
        generate_button = MDRaisedButton(text="Generate", on_press=lambda x: self.change_screen('generate'))
        saved_button = MDRaisedButton(text="Saved", on_press=lambda x: self.change_screen('saved'))
        check_button = MDRaisedButton(text="Check", on_press=lambda x: self.change_screen('check'))

        bottom_nav_bar.add_widget(generate_button)
        bottom_nav_bar.add_widget(saved_button)
        bottom_nav_bar.add_widget(check_button)

        layout.add_widget(self.sm)
        layout.add_widget(bottom_nav_bar)

        return layout

    def change_screen(self, screen_name):
        self.sm.current = screen_name

    def save_password(self, service, password, email):
        with open(password_file, 'a') as f:
            f.write(f"Service: {service} | Password: {password} | Email: {email}\n")

    def load_saved_passwords(self):
        if os.path.exists(password_file):
            with open(password_file, 'r') as f:
                self.passwords_list_text = f.read()

    def search_password_by_service(self, service_name):
        with open(password_file, 'r') as f:
            passwords = f.readlines()

        search_results = [pw for pw in passwords if service_name.lower() in pw.lower()]
        self.sm.get_screen('saved').populate_passwords("\n".join(search_results))


if __name__ == '__main__':
    load_rockyou()
    PasswordManagerApp().run()
