import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ======================== ЛОГИКА ШИФРОВАНИЯ ========================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_message(password: str, plaintext: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_data = salt + nonce + ciphertext + tag
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(password: str, encrypted_b64: str) -> str:
    encrypted_data = base64.b64decode(encrypted_b64)
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[28:-16]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# ======================== ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ========================

class EncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Надёжный шифровальщик AES-256-GCM")
        self.root.geometry("700x650")
        self.root.resizable(True, True)

        # Пароль
        tk.Label(root, text="Пароль (ключ):", font=("Arial", 12)).pack(pady=(10, 0))
        self.password_entry = tk.Entry(root, show="*", width=50, font=("Arial", 12))
        self.password_entry.pack(pady=5)

        # Метка для текстового поля
        tk.Label(root, text="Текст сообщения:", font=("Arial", 12)).pack(pady=(10, 0))

        # ---------- РАМКА С КНОПКАМИ КОПИРОВАНИЯ/ВСТАВКИ ----------
        button_frame_top = tk.Frame(root)
        button_frame_top.pack(pady=5)

        self.copy_btn = tk.Button(button_frame_top, text="📋 Скопировать выделенное",
                                  command=self.copy_selection,
                                  bg="#e7e7e7", width=18)
        self.copy_btn.pack(side=tk.LEFT, padx=5)

        self.paste_btn = tk.Button(button_frame_top, text="📋 Вставить из буфера",
                                   command=self.paste_from_clipboard,
                                   bg="#e7e7e7", width=18)
        self.paste_btn.pack(side=tk.LEFT, padx=5)
        # ---------------------------------------------------------

        # Текстовое поле
        self.text_area = scrolledtext.ScrolledText(root, height=10, font=("Arial", 11))
        self.text_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Привязка Ctrl+C (оставляем для удобства)
        self.text_area.bind('<Control-c>', self.copy_selection)
        self.text_area.bind('<Control-C>', self.copy_selection)

        # Кнопки основных действий
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.encrypt_btn = tk.Button(button_frame, text="🔒 Зашифровать", command=self.encrypt,
                                     bg="#4CAF50", fg="white", width=15, height=2, font=("Arial", 11))
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)

        self.decrypt_btn = tk.Button(button_frame, text="🔓 Расшифровать", command=self.decrypt,
                                     bg="#2196F3", fg="white", width=15, height=2, font=("Arial", 11))
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)

        self.clear_btn = tk.Button(button_frame, text="🗑️ Очистить", command=self.clear_text,
                                   bg="#f44336", fg="white", width=15, height=2, font=("Arial", 11))
        self.clear_btn.pack(side=tk.LEFT, padx=10)

        self.exit_btn = tk.Button(button_frame, text="🚪 Выход", command=self.exit_app,
                                  bg="#555555", fg="white", width=15, height=2, font=("Arial", 11))
        self.exit_btn.pack(side=tk.LEFT, padx=10)

        # Кнопки работы с файлами
        file_frame = tk.Frame(root)
        file_frame.pack(pady=5)

        self.load_btn = tk.Button(file_frame, text="📂 Загрузить из файла", command=self.load_from_file,
                                  bg="#FF9800", fg="white", width=18, height=1, font=("Arial", 10))
        self.load_btn.pack(side=tk.LEFT, padx=10)

        self.save_btn = tk.Button(file_frame, text="💾 Сохранить в файл", command=self.save_to_file,
                                  bg="#9C27B0", fg="white", width=18, height=1, font=("Arial", 10))
        self.save_btn.pack(side=tk.LEFT, padx=10)

        # Статусная строка
        self.status_label = tk.Label(root, text="Готов к работе.", bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                     font=("Arial", 9))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------- МЕТОДЫ КОПИРОВАНИЯ И ВСТАВКИ ----------
    def copy_selection(self, event=None):
        """Копирует выделенный текст в буфер обмена."""
        try:
            selected = self.text_area.get(tk.SEL_FIRST, tk.SEL_LAST)
            if selected:
                self.root.clipboard_clear()
                self.root.clipboard_append(selected)
                self.set_status("✅ Выделенный текст скопирован.")
            else:
                self.set_status("❌ Ничего не выделено.")
        except tk.TclError:
            self.set_status("❌ Ничего не выделено.")
        return "break"  # предотвращает стандартное поведение

    def paste_from_clipboard(self):
        """Вставляет текст из буфера обмена в текущую позицию курсора."""
        try:
            clipboard_text = self.root.clipboard_get()
            if clipboard_text:
                # Вставляем в место курсора
                self.text_area.insert(tk.INSERT, clipboard_text)
                self.set_status("✅ Текст вставлен из буфера.")
            else:
                self.set_status("❌ Буфер обмена пуст.")
        except tk.TclError:
            self.set_status("❌ Буфер обмена пуст или недоступен.")
    # ------------------------------------------------

    def set_status(self, text, is_error=False):
        self.status_label.config(text=text, fg="red" if is_error else "black")

    def get_password(self):
        pwd = self.password_entry.get()
        if not pwd:
            messagebox.showerror("Ошибка", "Пожалуйста, введите пароль!")
            return None
        return pwd

    def encrypt(self):
        pwd = self.get_password()
        if not pwd:
            return
        plaintext = self.text_area.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showerror("Ошибка", "Нет текста для шифрования!")
            return
        try:
            encrypted_b64 = encrypt_message(pwd, plaintext)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", encrypted_b64)
            self.set_status("✅ Текст успешно зашифрован.")
        except Exception as e:
            self.set_status(f"❌ Ошибка шифрования: {e}", is_error=True)
            messagebox.showerror("Ошибка", f"Не удалось зашифровать:\n{e}")

    def decrypt(self):
        pwd = self.get_password()
        if not pwd:
            return
        encrypted_b64 = self.text_area.get("1.0", tk.END).strip()
        if not encrypted_b64:
            messagebox.showerror("Ошибка", "Нет данных для расшифровки!")
            return
        try:
            plaintext = decrypt_message(pwd, encrypted_b64)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", plaintext)
            self.set_status("✅ Текст успешно расшифрован.")
        except InvalidTag:
            self.set_status("❌ Ошибка: Неверный пароль или данные повреждены!", is_error=True)
            messagebox.showerror("Ошибка", "Неверный пароль или зашифрованные данные были изменены.")
        except Exception as e:
            self.set_status(f"❌ Ошибка расшифровки: {e}", is_error=True)
            messagebox.showerror("Ошибка", f"Не удалось расшифровать:\n{e}")

    def clear_text(self):
        self.text_area.delete("1.0", tk.END)
        self.set_status("Текст очищен.")

    def load_from_file(self):
        filepath = filedialog.askopenfilename(
            title="Выберите текстовый файл",
            filetypes=(("Текстовые файлы", "*.txt"), ("Все файлы", "*.*"))
        )
        if not filepath:
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", content)
            self.set_status(f"✅ Загружен файл: {os.path.basename(filepath)}")
        except Exception as e:
            self.set_status(f"❌ Ошибка загрузки: {e}", is_error=True)
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}")

    def save_to_file(self):
        content = self.text_area.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Ошибка", "Нет данных для сохранения!")
            return
        filepath = filedialog.asksaveasfilename(
            title="Сохранить как...",
            defaultextension=".txt",
            filetypes=(("Текстовые файлы", "*.txt"), ("Все файлы", "*.*"))
        )
        if not filepath:
            return
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            self.set_status(f"✅ Сохранено в: {os.path.basename(filepath)}")
        except Exception as e:
            self.set_status(f"❌ Ошибка сохранения: {e}", is_error=True)
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def exit_app(self):
        """Закрывает приложение."""
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()