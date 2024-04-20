import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os
import time
import pyrebase
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore 

# Firebase configuration
firebaseConfig = {
  "apiKey": "AIzaSyCzkspjaujisW947wqiQ2vT2tHCsRmy8n4",
  "databaseURL":"https://authentication-bc744-default-rtdb.firebaseio.com/",
  "authDomain": "authentication-bc744.firebaseapp.com",
  "projectId": "authentication-bc744",
  "storageBucket": "authentication-bc744.appspot.com",
  "messagingSenderId": "886215037231",
  "appId": "1:886215037231:web:f8242c2d01c0eef45d91da",
  "measurementId": "G-87NJNRNJL4"
}

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
# Initialize Firebase Admin with your credentials
cred = credentials.Certificate(r"C:\Users\123su\OneDrive\Desktop\authentication-bc744-firebase-adminsdk-n845o-8083d1dbf6.json")
firebase_admin.initialize_app(cred)

# Initialize Firestore database
db = firestore.client()

# Initialize the selected file path as None
selected_file_path = None

# Initialize time labels as global variables
encryption_time_label = None
decryption_time_label = None

# Initialize the counter for CTR mode
def initialize_ctr_counter(nonce, block_size=16):
    return Counter.new(64, prefix=nonce, little_endian=True, allow_wraparound=False)

def encrypt_aes_256_ctr(key, data, nonce):
    cipher = AES.new(key.encode(), AES.MODE_CTR, counter=initialize_ctr_counter(nonce))
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_aes_256_ctr(key, data, nonce):
    cipher = AES.new(key.encode(), AES.MODE_CTR, counter=initialize_ctr_counter(nonce))
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

# Initialize a nonce (IV) once
nonce = os.urandom(8)

# Initialize start_time
start_time = 0

def browse_file():
    global selected_file_path, file_path_label
    selected_file_path = filedialog.askopenfilename(title='Select Image')
    if file_path_label is not None:
        file_path_label.config(text='Selected File: ' + selected_file_path)

def perform_encryption():
    global start_time, encryption_time_label, decryption_time_label

    if selected_file_path is None:
        status_label.config(text='Please select a file first')
        return

    key = key_entry.get()
    if len(key) != 16:
        status_label.config(text='Key must be in appropriate length')
        return

    try:
        # Display the encryption start time
        start_time = time.time()

        with open(selected_file_path, 'rb') as fin:
            with open(selected_file_path + '.enc', 'wb') as fout:
                cipher = AES.new(key.encode(), AES.MODE_CTR, counter=initialize_ctr_counter(nonce))
                chunk_size = 8192
                while chunk := fin.read(chunk_size):
                    fout.write(cipher.encrypt(chunk))

        os.replace(selected_file_path + '.enc', selected_file_path)

        status_label.config(text='Encryption Done...')

        # Display the encryption time
        end_time = time.time()
        elapsed_time = end_time - start_time
        if encryption_time_label:
            encryption_time_label.destroy()
        encryption_time_label = tk.Label(window, text=f'Encryption Time: {elapsed_time:.4f} seconds', fg='green', bg='#ADD8E6')
        encryption_time_label.pack(pady=10)

    except Exception as e:
        status_label.config(text='Error caught: ' + str(e))

def perform_decryption():
    global start_time, encryption_time_label, decryption_time_label

    if selected_file_path is None:
        status_label.config(text='Please select a file first')
        return

    key = key_entry.get()
    if len(key) != 16:
        status_label.config(text='Key must be in appropriate length')
        return

    try:
        # Display the decryption start time
        start_time = time.time()

        with open(selected_file_path, 'rb') as fin:
            with open(selected_file_path + '.dec', 'wb') as fout:
                cipher = AES.new(key.encode(), AES.MODE_CTR, counter=initialize_ctr_counter(nonce))
                chunk_size = 8192
                while chunk := fin.read(chunk_size):
                    fout.write(cipher.decrypt(chunk))

        os.replace(selected_file_path + '.dec', selected_file_path)

        status_label.config(text='Decryption Done...')

        # Display the decryption time
        end_time = time.time()
        elapsed_time = end_time - start_time
        if decryption_time_label:
            decryption_time_label.destroy()
        decryption_time_label = tk.Label(window, text=f'Decryption Time: {elapsed_time:.4f} seconds', fg='green', bg='#ADD8E6')
        decryption_time_label.pack(pady=10)

    except Exception as e:
        status_label.config(text='Error caught: ' + str(e))
        if "padding" in str(e).lower():
            status_label.config(text='Decryption Error: Incorrect Key or Corrupted Data')

def send_email():
    sender_email = sender_email_entry.get()
    sender_password = sender_password_entry.get()
    receiver_email = receiver_email_entry.get()
    subject = subject_entry.get()
    message = message_text.get("1.0", "end-1c")

    try:
        if not sender_email or not sender_password or not receiver_email or not subject or not message or selected_file_path is None:
            messagebox.showerror("Error", "Please fill in all fields and attach a file.")
            return

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        file_name = os.path.basename(selected_file_path)

        with open(selected_file_path, "rb") as attachment:
            part = MIMEApplication(attachment.read(), Name=file_name)
            part['Content-Disposition'] = f'attachment; filename="{file_name}"'
            msg.attach(part)

        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login(sender_email, sender_password)
        smtp_server.sendmail(sender_email, receiver_email, msg.as_string())
        smtp_server.quit()
        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def switch_to_login_frame():
    reg_frame.pack_forget()
    auth_frame.pack()

def authenticate_and_start():
    global window
    username = username_entry.get()
    password = password_entry.get()

    try:
        user = auth.sign_in_with_email_and_password(username, password)
        user_info = auth.get_account_info(user['idToken'])
        if user_info['users'][0]['emailVerified']:
            messagebox.showinfo("Success", "Successfully logged in!")
            auth_window.withdraw()  # Hide authentication window
            # Create the main GUI window
            create_main_window()
        else:
            messagebox.showerror("Email Verification Error", "Please verify your email address before logging in.")
    except Exception as e:
        messagebox.showerror("Authentication Error", "Invalid username or password")

def register_user():
    username = username_reg_entry.get()
    password = password_reg_entry.get()
    email = email_reg_entry.get()
    mobile = mobile_reg_entry.get()

    try:
        # Create user in Firebase Authentication
        auth.create_user_with_email_and_password(email, password)
        
        # Authenticate user
        user = auth.sign_in_with_email_and_password(email, password)
        
        # Send email verification
        auth.send_email_verification(user['idToken'])

        # Store user data in Firestore
        user_data = {
            'username': username,
            'email': email,
            'mobile': mobile,
            'password': password
        }
        
        # Use Firestore's `collection` method to reference a collection
        users_ref = db.collection('users')
        # Add a new document with a generated ID
        users_ref.add(user_data)

        # Display success message and switch to login frame
        messagebox.showinfo("Success", "Successfully registered! A verification email has been sent to your email address.")
        switch_to_login_frame()
    except Exception as e:
        # Display error message if registration fails
        messagebox.showerror("Registration Error", f"Registration failed: {str(e)}")

def reset_password():
    reset_password_window = tk.Toplevel(auth_window)
    reset_password_window.title("Reset Password")
    reset_password_window.geometry("300x150")
    reset_password_window.configure(background='#ADD8E6')

    email_label = ttk.Label(reset_password_window, text="Email:", font=('Comfortaa', 12, 'bold'), background='#ADD8E6')
    email_label.grid(row=0, column=0, padx=10, pady=5)

    email_entry = ttk.Entry(reset_password_window)
    email_entry.grid(row=0, column=1, padx=10, pady=5)

    reset_button = ttk.Button(reset_password_window, text="Reset Password", command=lambda: reset_user_password(email_entry.get()), style='Custom.TButton')
    reset_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    back_button = ttk.Button(reset_password_window, text="Back to Login", command=reset_password_window.destroy, style='Custom.TButton')
    back_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

def reset_user_password(email):
    try:
        auth.send_password_reset_email(email)
        messagebox.showinfo("Password Reset", "Password reset email sent successfully!")
    except Exception as e:
        messagebox.showerror("Password Reset Error", f"Password reset failed: {str(e)}")

def create_main_window():
    global window
    # Create the main GUI window
    window = tk.Tk()
    window.title('Advance Data Encryption And Security')
    window.geometry('800x600')
    window.configure(background='#ADD8E6')

    # Add the app name label
    app_name_label = tk.Label(window, text='Advance Data Encryption And Security', font=('Helvetica', 16, 'bold') , bg='#ADD8E6')
    app_name_label.pack(pady=10)

    notebook = ttk.Notebook(window)
    notebook.pack(fill='both', expand=True)

    email_sender_frame = ttk.Frame(notebook)
    notebook.add(email_sender_frame, text='Email Sender')

    style = ttk.Style()
    style.configure('email.TFrame', background='#ADD8E6')
    email_sender_frame.configure(style='email.TFrame')


    button_style_email_sender = ttk.Style()
    button_style_email_sender.configure('EmailSender.TButton', background='lightblue', foreground='black', padding=10)
    sender_email_label = tk.Label(email_sender_frame, text="Sender Email:")
    sender_email_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    global sender_email_entry
    sender_email_entry = tk.Entry(email_sender_frame)
    sender_email_entry.grid(row=0, column=1, padx=10, pady=5)

    sender_password_label = tk.Label(email_sender_frame, text="Password:")
    sender_password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

    global sender_password_entry
    sender_password_entry = tk.Entry(email_sender_frame, show="*")
    sender_password_entry.grid(row=1, column=1, padx=10, pady=5)

    receiver_email_label = tk.Label(email_sender_frame, text="Receiver Email:")
    receiver_email_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

    global receiver_email_entry
    receiver_email_entry = tk.Entry(email_sender_frame)
    receiver_email_entry.grid(row=2, column=1, padx=10, pady=5)

    subject_label = tk.Label(email_sender_frame, text="Subject:")
    subject_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

    global subject_entry
    subject_entry = tk.Entry(email_sender_frame)
    subject_entry.grid(row=3, column=1, padx=10, pady=5)

    message_label = tk.Label(email_sender_frame, text="Message:")
    message_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")

    global message_text
    message_text = tk.Text(email_sender_frame, height=5, width=40)
    message_text.grid(row=4, column=1, padx=10, pady=5)

    attach_button = ttk.Button(email_sender_frame, text="Attach File", command=browse_file, style='EmailSender.TButton')
    attach_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

    send_button = ttk.Button(email_sender_frame, text="Send Email", command=send_email, style='EmailSender.TButton')
    send_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    encryption_frame = ttk.Frame(notebook)
    notebook.add(encryption_frame, text='Encryption/Decryption')

    encryption_frame.configure(style='email.TFrame')

    button_style_encryption = ttk.Style()
    button_style_encryption.configure('Encryption.TButton', background='lightgreen', foreground='black', padding=10)
    key_label = tk.Label(encryption_frame, text='Enter AES Key in an appropriate length:')
    key_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    global key_entry
    key_entry = tk.Entry(encryption_frame, show='*')
    key_entry.grid(row=0, column=1, padx=10, pady=5)

    choose_file_button = ttk.Button(encryption_frame, text='Choose File', command=browse_file, style='Encryption.TButton')
    choose_file_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

    encrypt_button = ttk.Button(encryption_frame, text='Encrypt', command=perform_encryption, style='Encryption.TButton')
    encrypt_button.grid(row=2, column=0, padx=10, pady=5)

    decrypt_button = ttk.Button(encryption_frame, text='Decrypt', command=perform_decryption, style='Encryption.TButton')
    decrypt_button.grid(row=2, column=1, padx=10, pady=5)

    global file_path_label, status_label
    file_path_label = tk.Label(window, text='Selected File: None', wraplength=400, bg='#f0f0f0')
    file_path_label.pack(pady=10)

    status_label = tk.Label(window, text='', fg='blue', bg='#f0f0f0')
    status_label.pack(pady=10)

    window.mainloop()

# Create the authentication window
auth_window = tk.Tk()
auth_window.title("Advance Data Encryption And Security - Authentication")

# Set the size of the authentication window
auth_window.geometry('800x600')  # Set width to 400 pixels and height to 250 pixels
auth_window.configure(background='#ADD8E6')

# Add the app name label
app_name_label = tk.Label(auth_window, text='Advance Data Encryption And Security', font=('Helvetica', 32, 'bold'), bg='#ADD8E6')
app_name_label.pack(pady=10)

# Authentication frame
auth_frame = ttk.Frame(auth_window)
auth_frame.pack()

# Registration frame
reg_frame = ttk.Frame(auth_window)

username_label = ttk.Label(auth_frame, text="Email:", font=('Comfortaa', 12, 'bold'))
username_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

username_entry = ttk.Entry(auth_frame)
username_entry.grid(row=0, column=1, padx=10, pady=5)

password_label = ttk.Label(auth_frame, text="Password:", font=('Comfortaa', 12, 'bold'))
password_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

password_entry = ttk.Entry(auth_frame, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=5)

login_button = ttk.Button(auth_frame, text="Login", command=authenticate_and_start, style='Custom.TButton')
login_button.grid(row=2, column=0, pady=10)

# Password reset button
reset_password_button = ttk.Button(auth_frame, text="Reset Password", command=reset_password, style='Custom.TButton')
reset_password_button.grid(row=2, column=1, pady=10)

register_label = ttk.Label(auth_frame, text="Don't have an account? Register:")
register_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

register_button = ttk.Button(auth_frame, text="Sign Up", command=lambda: (auth_frame.pack_forget(), reg_frame.pack()), style='Custom.TButton')
register_button.grid(row=3, column=1, pady=5)

username_reg_label = ttk.Label(reg_frame, text="Username:", font=('Comfortaa', 12, 'bold'))
username_reg_label.grid(row=0, column=0, padx=10, pady=2, sticky="w")

username_reg_entry = ttk.Entry(reg_frame)
username_reg_entry.grid(row=0, column=1, padx=10, pady=5)

password_reg_label = ttk.Label(reg_frame, text="Password:", font=('Comfortaa', 12, 'bold'))
password_reg_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

password_reg_entry = ttk.Entry(reg_frame, show="*")
password_reg_entry.grid(row=1, column=1, padx=10, pady=5)

email_reg_label = ttk.Label(reg_frame, text="Email:", font=('Comfortaa', 12, 'bold'))
email_reg_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

email_reg_entry = ttk.Entry(reg_frame)
email_reg_entry.grid(row=2, column=1, padx=1, pady=5)

mobile_reg_label = ttk.Label(reg_frame, text="Mobile:", font=('Comfortaa', 12, 'bold'))
mobile_reg_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

mobile_reg_entry = ttk.Entry(reg_frame)
mobile_reg_entry.grid(row=3, column=1, padx=10, pady=5)

register_button = ttk.Button(reg_frame, text="Register", command=register_user, style='Custom.TButton')
register_button.grid(row=4, column=0, pady=10)

back_to_login_button = ttk.Button(reg_frame, text="Back to Login", command=switch_to_login_frame, style='Custom.TButton')
back_to_login_button.grid(row=4, column=1, pady=10)

# Define custom style for the button
custom_button_style = ttk.Style()
custom_button_style.configure('Custom.TButton', foreground='black', background='#4CAF50', font=('Helvetica', 10, 'bold'), padding=1)

# Run the Tkinter main loop
auth_window.mainloop()
