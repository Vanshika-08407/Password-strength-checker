
'''
Write a program that checks the strength of a password based on the following criteria:
At least 8 characters long
Contains both uppercase and lowercase characters
Contains at least one digit
Contains at least one special character (e.g., !, @, #, $, etc.)
'''
import hashlib
import re
import streamlit as st

st.set_page_config(page_title="Password Checker", page_icon="🔍")

# Password checking logic
def password_checker(password):
    if len(password) < 8:
        return "Weak: Password should be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return "Weak: Password must contain an uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Weak: Password must contain a lowercase letter"
    if not re.search(r"\d", password):
        return "Weak: Password must contain a digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: Password must contain a special character"
    
    return "Strong password"
def hash_password(password):
    hash = hashlib.sha256(password.encode()).hexdigest()
    return hash
# Streamlit page config
st.title("🔍 Password Strength Checker")

# Input from user
user_input = st.text_input("Enter your password:")

# On button click
if st.button("Check Password"):
    if user_input.strip():
        result = password_checker(user_input.strip())

        if "Weak" in result:
            st.error(result)
        else:
            st.success(result)
    else:
        st.warning("⚠️ Please enter a password to check.")
if user_input:
    if st.checkbox("hashed value for the pass is :"):
        hashed_pass = hash_password(user_input)
        st.code(hashed_pass,language="bash")

