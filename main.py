import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ----------------------------- Setup -----------------------------
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "users" not in st.session_state:
    st.session_state.users = {}  # Store usernames and hashed passwords

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

# --------------------------- Functions ---------------------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_password(passkey)

    for key, value in st.session_state.stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0  # Reset attempts
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# ----------------------------- UI -----------------------------

st.title("🛡️ Secure Data Encryption System")

# ------------------------- Login / Register -------------------------

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

    # -------------------- Login Tab --------------------
    with tab1:
        st.subheader("User Login")
        login_name = st.text_input("Username")
        login_password = st.text_input("Password", type="password")

        if st.button("Login"):
            if login_name in st.session_state.users:
                if st.session_state.users[login_name] == hash_password(login_password):
                    st.session_state.logged_in = True
                    st.session_state.username = login_name
                    st.success(f"✅ Welcome back, {login_name}!")
                    st.rerun()
                else:
                    st.error("❌ Incorrect password.")
            else:
                st.error("❌ User not found. Please register.")

    # -------------------- Register Tab --------------------
    with tab2:
        st.subheader("New User Registration")
        new_name = st.text_input("Choose a username")
        new_password = st.text_input("Create a password", type="password")

        if st.button("Register"):
            if new_name in st.session_state.users:
                st.warning("⚠️ Username already exists. Try another one.")
            elif new_name and new_password:
                st.session_state.users[new_name] = hash_password(new_password)
                st.success("✅ Registration successful! Please log in now.")
            else:
                st.error("❗ Both fields are required.")

# ------------------------ Main App after Login ------------------------

else:
    st.sidebar.success(f"👤 Logged in as: {st.session_state.username}")
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome!")
        st.write(f"Hello **{st.session_state.username}**, this secure system allows you to:")
        st.markdown("""
        - 🔐 Encrypt and store sensitive data  
        - 🔓 Retrieve your data using a secret passkey  
        - ⛔ Lock access after 3 failed attempts
        """)

    elif choice == "Store Data":
        st.subheader("📂 Store New Data")
        user_data = st.text_area("Enter your data here:")
        passkey = st.text_input("Create a passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed = hash_password(passkey)
                encrypted = encrypt_data(user_data)
                st.session_state.stored_data[encrypted] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                st.success("✅ Data encrypted and stored successfully!")
                st.code(encrypted, language='text')
            else:
                st.error("❗ Both fields are required!")

    elif choice == "Retrieve Data":
        if st.session_state.failed_attempts >= 3:
            st.warning("🔒 Too many failed attempts. Please reauthorize.")
            st.session_state.logged_in = False
            st.rerun()

        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Paste your encrypted data:")
        passkey_input = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey_input:
                result = decrypt_data(encrypted_input, passkey_input)
                if result:
                    st.success("✅ Decryption successful!")
                    st.write("🔓 Your Data:")
                    st.code(result)
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔐 Locked out. Redirecting to login...")
                        st.session_state.logged_in = False
                        st.rerun()
            else:
                st.error("❗ Both fields are required.")

    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("👋 Logged out successfully.")
        st.rerun()
