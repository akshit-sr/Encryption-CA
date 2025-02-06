import tkinter as tk
from tkinter import messagebox
import os
import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

USER_DB_FILE = 'user_db.txt'
MESSAGE_DB_DIR = 'message_db'

if not os.path.exists(MESSAGE_DB_DIR):
    os.makedirs(MESSAGE_DB_DIR)

if not os.path.exists(USER_DB_FILE):
    with open(USER_DB_FILE, 'w') as f:
        f.write('{}')


def hash_password(password):
    """ Hashes password using SHA-256 """
    return hashlib.sha256(password.encode()).hexdigest()


def load_user_db():
    """ Loads user database from file """
    with open(USER_DB_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_user_db(user_db):
    """ Saves user database to file """
    with open(USER_DB_FILE, 'w') as f:
        json.dump(user_db, f, indent=4)


def register_user(username, password):
    """ Registers a new user with RSA key pair """
    user_db = load_user_db()
    if username in user_db:
        return False

    key_pair = RSA.generate(1024)
    user_db[username] = {
        'password': hash_password(password),
        'public_key': key_pair.publickey().export_key().decode(),
        'private_key': key_pair.export_key().decode(),
    }
    save_user_db(user_db)
    return True


def register():
    """ Handles user registration """
    username = entry_username.get()
    password = entry_password.get()
    if register_user(username, password):
        messagebox.showinfo('Register', 'Registered successfully!')
    else:
        messagebox.showerror('Register', 'Username already exists!')


def login():
    """ Handles user login """
    username = entry_username1.get()
    password = entry_password1.get()
    user_db = load_user_db()
    if username in user_db and user_db[username]['password'] == hash_password(password):
        messagebox.showinfo('Login', 'Login successful!')
        switch_to_chat_page(username)
    else:
        messagebox.showerror('Login', 'Invalid username or password!')


def send():
    """ Sends an encrypted message """
    sender = entry_sender.get()
    recipient = entry_recipient.get()
    message = entry_message.get()
    if send_message(sender, recipient, message):
        messagebox.showinfo('Send', 'Message sent successfully!')
        refresh_message()
    else:
        messagebox.showerror('Send', 'Recipient not found!')


def send_message(sender, recipient, message):
    """ Encrypts and stores the message for the recipient """
    user_db = load_user_db()
    if recipient not in user_db:
        return False

    public_key = RSA.import_key(user_db[recipient]['public_key'].encode())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())

    message_file = os.path.join(MESSAGE_DB_DIR, f'{recipient}.txt')
    with open(message_file, 'a') as f:
        f.write(json.dumps({'sender': sender, 'message': encrypted_message.hex()}) + "\n")
    return True


def receive_message(username):
    """ Decrypts and retrieves messages for the logged-in user """
    message_file = os.path.join(MESSAGE_DB_DIR, f'{username}.txt')
    if not os.path.exists(message_file):
        return []

    user_db = load_user_db()
    private_key = RSA.import_key(user_db[username]['private_key'].encode())
    messages = []

    with open(message_file, 'r') as f:
        for line in f:
            try:
                message_data = json.loads(line.strip())
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_message = cipher.decrypt(bytes.fromhex(message_data['message'])).decode()
            except ValueError:
                decrypted_message = "[DECRYPTION FAILED]"
            messages.append({'sender': message_data['sender'], 'message': decrypted_message})
    return messages


def refresh_message():
    """ Refreshes the message display for the logged-in user """
    username = entry_sender.get()
    messages = receive_message(username)
    message_display.delete('1.0', tk.END)
    for message in messages:
        message_display.insert(tk.END, f"{message['sender']}: {message['message']}\n")


def switch_to_register_page():
    """ Switches to the register page """
    login_frame.pack_forget()
    register_frame.pack()


def switch_to_login_page():
    """ Switches back to the login page """
    register_frame.pack_forget()
    chat_frame.pack_forget()
    login_frame.pack()


def switch_to_chat_page(username):
    """ Switches to the chat interface after successful login """
    login_frame.pack_forget()
    chat_frame.pack()
    entry_sender.config(state="normal")
    entry_sender.delete(0, tk.END)
    entry_sender.insert(0, username)
    entry_sender.config(state="readonly")
    refresh_message()


def logout():
    """ Logs out the user and returns to login screen """
    chat_frame.pack_forget()
    switch_to_login_page()


# GUI Setup
root = tk.Tk()
root.title('Secure Messaging System')

# Frames
login_frame = tk.Frame(root)
register_frame = tk.Frame(root)
chat_frame = tk.Frame(root)

# Login Page
label_username1 = tk.Label(login_frame, text='Username:')
entry_username1 = tk.Entry(login_frame)
label_password1 = tk.Label(login_frame, text='Password:')
entry_password1 = tk.Entry(login_frame, show='*')
button_login = tk.Button(login_frame, text='Login', command=login)
button_register = tk.Button(login_frame, text='Register', command=switch_to_register_page)

label_username1.pack()
entry_username1.pack()
label_password1.pack()
entry_password1.pack()
button_login.pack()
button_register.pack()

# Register Page
label_username = tk.Label(register_frame, text='Username:')
entry_username = tk.Entry(register_frame)
label_password = tk.Label(register_frame, text='Password:')
entry_password = tk.Entry(register_frame, show='*')
button_register = tk.Button(register_frame, text='Register', command=register)
button_login = tk.Button(register_frame, text='Back to Login', command=switch_to_login_page)

label_username.pack()
entry_username.pack()
label_password.pack()
entry_password.pack()
button_register.pack()
button_login.pack()

# Chat Page
label_sender = tk.Label(chat_frame, text='Sender:')
entry_sender = tk.Entry(chat_frame)
label_recipient = tk.Label(chat_frame, text='Recipient:')
entry_recipient = tk.Entry(chat_frame)
label_message = tk.Label(chat_frame, text='Message:')
entry_message = tk.Entry(chat_frame)
button_send = tk.Button(chat_frame, text='Send', command=send)
button_refresh = tk.Button(chat_frame, text='Refresh', command=refresh_message)
message_display = tk.Text(chat_frame, height=10, width=50)
button_logout = tk.Button(chat_frame, text='Logout', command=logout)

label_sender.pack()
entry_sender.pack()
label_recipient.pack()
entry_recipient.pack()
label_message.pack()
entry_message.pack()
button_send.pack()
button_refresh.pack()
message_display.pack()
button_logout.pack()

# Start with login page
switch_to_login_page()

# Run the GUI loop
root.mainloop()
