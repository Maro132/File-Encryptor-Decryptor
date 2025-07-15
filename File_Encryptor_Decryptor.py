import streamlit as st
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import io # Used for handling binary data streams

# --- Core encryption/decryption functions (now handle bytes directly) ---

def generate_encryption_key():
    """Generates a new Fernet key."""
    return Fernet.generate_key().decode()

def encrypt_data(data_bytes, key_str):
    """Encrypts bytes data using the provided Fernet key."""
    f = Fernet(key_str.encode())
    encrypted_data = f.encrypt(data_bytes)
    return encrypted_data

def decrypt_data(encrypted_data_bytes, key_str):
    """Decrypts bytes data using the provided Fernet key."""
    f = Fernet(key_str.encode())
    decrypted_data = f.decrypt(encrypted_data_bytes)
    return decrypted_data

# --- Streamlit User Interface ---

st.set_page_config(page_title="Secure File Encryptor/Decryptor", layout="centered")
st.title("Secure File Encryptor/Decryptor")
st.markdown("---")

# --- Key Generation Section ---
st.header("1. Generate Key")
col_key_gen_input, col_key_gen_btn = st.columns([3, 1])
with col_key_gen_input:
    # Use st.session_state to preserve key value across reruns
    if 'current_key' not in st.session_state:
        st.session_state.current_key = ""
    global_key_display_input = st.text_input("Generated Key", value=st.session_state.current_key, key="global_key_display")
with col_key_gen_btn:
    st.markdown("<br>", unsafe_allow_html=True) # Add some vertical space to align button
    if st.button("Generate New Key"):
        try:
            generated_key = generate_encryption_key()
            st.session_state.current_key = generated_key
            # Also update the encryption and decryption key fields directly for convenience
            st.session_state.encryption_key_field = generated_key
            st.session_state.decryption_key_field = generated_key
            st.rerun() # Rerun to update the text_input values
        except Exception as e:
            st.error(f"Error generating key: {e}")

st.markdown("---")

# --- File Encryption Section ---
st.header("2. Encrypt File")
col_encrypt_file, col_encrypt_key_input = st.columns([2, 1])

with col_encrypt_file:
    uploaded_file_encrypt = st.file_uploader("Upload File to Encrypt", type=None, key="encrypt_file_uploader") # type=None allows any file type

with col_encrypt_key_input:
    # Initialize session state for this specific key field
    if 'encryption_key_field' not in st.session_state:
        st.session_state.encryption_key_field = st.session_state.current_key if 'current_key' in st.session_state else ""
    encryption_key_input = st.text_input("Encryption Key", value=st.session_state.encryption_key_field, key="encryption_key_input_field")
    st.session_state.encryption_key_field = encryption_key_input # Update session state on user input

if st.button("Encrypt File", type="primary"):
    if uploaded_file_encrypt is not None and encryption_key_input:
        try:
            # Read file as bytes
            file_bytes = uploaded_file_encrypt.read()
            encrypted_bytes = encrypt_data(file_bytes, encryption_key_input)

            st.success("File encrypted successfully!")
            
            # Provide download button for the encrypted file
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_bytes,
                file_name=f"{uploaded_file_encrypt.name}.encrypted", # Add .encrypted extension
                mime="application/octet-stream", # Generic binary file type
                key="download_encrypted_file"
            )
            st.info("Remember to save your key! You'll need it to decrypt this file.")

        except Exception as e:
            st.error(f"Encryption error: {e}. Ensure the key is correct and the file is valid.")
    else:
        st.warning("Please upload a file and provide the encryption key.")

st.markdown("---")

# --- File Decryption Section ---
st.header("3. Decrypt File")
col_decrypt_file, col_decrypt_key_input = st.columns([2, 1])

with col_decrypt_file:
    uploaded_file_decrypt = st.file_uploader("Upload File to Decrypt", type=None, key="decrypt_file_uploader")

with col_decrypt_key_input:
    # Initialize session state for this specific key field
    if 'decryption_key_field' not in st.session_state:
        st.session_state.decryption_key_field = st.session_state.current_key if 'current_key' in st.session_state else ""
    decryption_key_input = st.text_input("Decryption Key", value=st.session_state.decryption_key_field, key="decryption_key_input_field")
    st.session_state.decryption_key_field = decryption_key_input # Update session state on user input

if st.button("Decrypt File", type="secondary"):
    if uploaded_file_decrypt is not None and decryption_key_input:
        try:
            # Read encrypted file as bytes
            encrypted_file_bytes = uploaded_file_decrypt.read()
            decrypted_bytes = decrypt_data(encrypted_file_bytes, decryption_key_input)

            st.success("File decrypted successfully!")

            # Determine original file name (remove .encrypted if present)
            original_file_name = uploaded_file_decrypt.name
            if original_file_name.endswith(".encrypted"):
                original_file_name = original_file_name[:-len(".encrypted")]

            # Provide download button for the decrypted file
            st.download_button(
                label="Download Decrypted File",
                data=decrypted_bytes,
                file_name=f"decrypted_{original_file_name}", # Prefix with decrypted_
                mime="application/octet-stream",
                key="download_decrypted_file"
            )

        except InvalidToken:
            st.error("Error: Invalid key or corrupted file. Please ensure the correct key is used.")
        except Exception as e:
            st.error(f"Decryption error: {e}. Ensure the key is correct and the file is valid.")
    else:
        st.warning("Please upload an encrypted file and provide the decryption key.")

st.markdown("---")
st.info("Note: This app uses secure Fernet encryption. The key is essential for encryption and decryption.")
