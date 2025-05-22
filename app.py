# Python Assignment: Secure Data Encryption System Using Streamlit
# Objective
# Develop a Streamlit-based secure data storage and retrieval system where:

# Users store data with a unique passkey.
# Users decrypt data by providing the correct passkey.
# Multiple failed attempts result in a forced reauthorization (login page).
# The system operates entirely in memory without external databases.
import streamlit as st              
from cryptography.fernet import Fernet
import base64
import os
import hashlib
import json
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
# data information
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
Lockout_time = 60 
# login details
if "authenticate_user" not in st.session_state:
    st.session_state.authenticate_user = None
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "Lockout_time" not in st.session_state:
    st.session_state.Lockout_time = 0
# if ===data is loaded===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}
# if ===data is saved===
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)
def generate_key(password):
    key=pbkdf2_hmac(
        "sha256",
        password.encode(),
        SALT,
        100000,
    )
    return urlsafe_b64encode(key)
def hash_password(password):
    return hashlib.pbkdf2_hmac  (
        "sha256",
        password.encode(),
        SALT,
        100000,
    )
# === cryptography.fernet used ===
def encrypt_text(text, password):
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(text.encode()).decode()
def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()
# ===navigation===
st.title("Secure Data Encryption System")
menu = ["Home", "Register","Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)
if choice == "Home":
    st.subheader("Welcome to the Secure Data🔐 Encryption System")
    st.markdown("This system allows you to securely store with Passkey and decrpyt data with correct password"
    " and retrieve data using encryption.")
# user registration
elif choice == "Register":
    st.subheader("User Registration")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("⚠️Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": {}
                }
                save_data(stored_data)
                st.success("✅User registered successfully.")
        else:
            st.error("Please enter both username and password.")
elif choice == "Login":
    st.subheader("🗝️User Login")
    if time.time() < st.session_state.Lockout_time:
        remaining_time = int(st.session_state.Lockout_time - time.time())
        st.error(f"⚠️Too many failed attempts. Please wait {remaining_time} seconds before trying again.")
        st.stop()
    username = st.text_input("Username")    
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticate_user = username
            st.session_state.login_attempts = 0
            st.success("✅Login successful.")
        else:
            st.session_state.login_attempts += 1
            remaining = 3 - st.session_state.login_attempts
            st.error(f"⚠️Incorrect username or password. {remaining} attempts left.")
            if st.session_state.login_attempts >= 3:
                st.session_state.Lockout_time = time.time() + Lockout_time
                st.error("⚠️Too many failed attempts. Please wait before trying again.")
                st.stop()
elif choice == "Store Data":
    if not st.session_state.authenticate_user:
        st.error("Please login to store data.")
    else:
        st.subheader("🔐Store Encrypted Data")
        data = st.text_area(" Enter Data to encrypt")
        password = st.text_input("Enter Passkey", type="password")
        if st.button("Encrypt and Store"):
            if data and password:
                encrypted_data = encrypt_text(data, password)
                stored_data[st.session_state.authenticate_user]["data"][password] = encrypted_data
                save_data(stored_data)
                st.success("✅Data stored successfully.")
            else:
                st.error("Please enter both data and passkey.")
elif choice == "Retrieve Data":
    if not st.session_state.authenticate_user:
        st.error("Please login to retrieve data.")
    else:
        st.subheader("🔑Retrieve Decrypted Data")
        user_data = stored_data.get(st.session_state.authenticate_user, {}).get("data", {})
        if not user_data:
            st.info("⚠️No data found for the current user.")
        else:
            st.write("Encrypted data Entries:")
            for i, encrypted_data in enumerate(user_data):
                st.code(encrypted_data, language="text")
                password = st.text_input("Enter Passkey", type="password")
                if st.button("Decrypt"):
                    result = decrypt_text(encrypted_data, password)
                if result:
                    st.success(f"✅Decrypted Data: {result}")
                else:
                    st.error("⚠️Failed to decrypt data. Incorrect passkey.")