import streamlit as st
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Page configuration
st.set_page_config(
    page_title="Secure Data Encryption",
    page_icon="🔐",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #4CAF50;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
    }
    .success-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .error-box {
        padding: 1rem;
        border-radius: 5px;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
    </style>
""", unsafe_allow_html=True)

class SecureEncryption:
    """Advanced encryption handler with multiple algorithms"""
    
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = hashlib.pbkdf2_hmac(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_fernet(data: str, password: str) -> dict:
        """Encrypt using Fernet (symmetric encryption)"""
        try:
            key, salt = SecureEncryption.generate_key_from_password(password)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data.encode())
            
            return {
                'success': True,
                'encrypted': base64.b64encode(encrypted).decode(),
                'salt': base64.b64encode(salt).decode(),
                'algorithm': 'Fernet (AES-128)'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def decrypt_fernet(encrypted_data: str, password: str, salt: str) -> dict:
        """Decrypt using Fernet"""
        try:
            salt_bytes = base64.b64decode(salt)
            key, _ = SecureEncryption.generate_key_from_password(password, salt_bytes)
            fernet = Fernet(key)
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = fernet.decrypt(encrypted_bytes)
            
            return {
                'success': True,
                'decrypted': decrypted.decode()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def encrypt_aes_256(data: str, password: str) -> dict:
        """Encrypt using AES-256-GCM"""
        try:
            salt = secrets.token_bytes(16)
            key, _ = SecureEncryption.generate_key_from_password(password, salt)
            key_bytes = base64.urlsafe_b64decode(key)
            
            iv = secrets.token_bytes(12)
            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
            
            return {
                'success': True,
                'encrypted': base64.b64encode(ciphertext).decode(),
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(encryptor.tag).decode(),
                'algorithm': 'AES-256-GCM'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def decrypt_aes_256(encrypted_data: str, password: str, salt: str, iv: str, tag: str) -> dict:
        """Decrypt using AES-256-GCM"""
        try:
            salt_bytes = base64.b64decode(salt)
            key, _ = SecureEncryption.generate_key_from_password(password, salt_bytes)
            key_bytes = base64.urlsafe_b64decode(key)
            
            iv_bytes = base64.b64decode(iv)
            tag_bytes = base64.b64decode(tag)
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.GCM(iv_bytes, tag_bytes),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            return {
                'success': True,
                'decrypted': decrypted.decode()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def hash_data(data: str, algorithm: str = 'SHA-256') -> str:
        """Generate hash of data"""
        hash_funcs = {
            'SHA-256': hashlib.sha256,
            'SHA-512': hashlib.sha512,
            'SHA3-256': hashlib.sha3_256,
            'BLAKE2b': hashlib.blake2b
        }
        
        hash_func = hash_funcs.get(algorithm, hashlib.sha256)
        return hash_func(data.encode()).hexdigest()


def main():
    st.title("🔐 Secure Data Encryption System")
    st.markdown("### Advanced encryption with multiple algorithms")
    
    # Sidebar for mode selection
    with st.sidebar:
        st.header("⚙️ Configuration")
        mode = st.radio("Select Mode", ["Encrypt", "Decrypt", "Hash"])
        
        if mode in ["Encrypt", "Decrypt"]:
            algorithm = st.selectbox(
                "Encryption Algorithm",
                ["Fernet (AES-128)", "AES-256-GCM"]
            )
        
        st.markdown("---")
        st.markdown("### 📊 Security Features")
        st.markdown("""
        - 🔒 PBKDF2 key derivation
        - 🔑 100,000 iterations
        - 🛡️ Cryptographically secure random
        - ✅ Industry-standard algorithms
        """)
    
    # Main content
    if mode == "Encrypt":
        st.header("🔒 Encrypt Data")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            data_input = st.text_area("Enter data to encrypt", height=150, key="encrypt_data")
            password = st.text_input("Enter password", type="password", key="encrypt_pass")
            
            if st.button("🔐 Encrypt", key="encrypt_btn"):
                if data_input and password:
                    if len(password) < 8:
                        st.error("⚠️ Password must be at least 8 characters long")
                    else:
                        with st.spinner("Encrypting..."):
                            if algorithm == "Fernet (AES-128)":
                                result = SecureEncryption.encrypt_fernet(data_input, password)
                            else:
                                result = SecureEncryption.encrypt_aes_256(data_input, password)
                            
                            if result['success']:
                                st.success("✅ Encryption successful!")
                                
                                st.subheader("📝 Encrypted Data")
                                st.code(result['encrypted'], language=None)
                                
                                st.subheader("🔑 Salt (Keep this safe!)")
                                st.code(result['salt'], language=None)
                                
                                if 'iv' in result:
                                    st.subheader("🎲 IV (Initialization Vector)")
                                    st.code(result['iv'], language=None)
                                    
                                    st.subheader("🏷️ Authentication Tag")
                                    st.code(result['tag'], language=None)
                                
                                st.info(f"🔒 Algorithm used: {result['algorithm']}")
                            else:
                                st.error(f"❌ Encryption failed: {result['error']}")
                else:
                    st.warning("⚠️ Please enter both data and password")
        
        with col2:
            st.info("""
            **💡 Tips:**
            - Use strong passwords (8+ chars)
            - Save salt & IV for decryption
            - Don't share encrypted data and password together
            """)
    
    elif mode == "Decrypt":
        st.header("🔓 Decrypt Data")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            encrypted_input = st.text_area("Enter encrypted data", height=100, key="decrypt_data")
            password = st.text_input("Enter password", type="password", key="decrypt_pass")
            salt_input = st.text_input("Enter salt", key="decrypt_salt")
            
            if algorithm == "AES-256-GCM":
                iv_input = st.text_input("Enter IV", key="decrypt_iv")
                tag_input = st.text_input("Enter authentication tag", key="decrypt_tag")
            
            if st.button("🔓 Decrypt", key="decrypt_btn"):
                if algorithm == "Fernet (AES-128)":
                    if encrypted_input and password and salt_input:
                        with st.spinner("Decrypting..."):
                            result = SecureEncryption.decrypt_fernet(encrypted_input, password, salt_input)
                            
                            if result['success']:
                                st.success("✅ Decryption successful!")
                                st.subheader("📝 Decrypted Data")
                                st.text_area("Result", result['decrypted'], height=150)
                            else:
                                st.error(f"❌ Decryption failed: {result['error']}")
                    else:
                        st.warning("⚠️ Please fill all fields")
                else:
                    if encrypted_input and password and salt_input and iv_input and tag_input:
                        with st.spinner("Decrypting..."):
                            result = SecureEncryption.decrypt_aes_256(
                                encrypted_input, password, salt_input, iv_input, tag_input
                            )
                            
                            if result['success']:
                                st.success("✅ Decryption successful!")
                                st.subheader("📝 Decrypted Data")
                                st.text_area("Result", result['decrypted'], height=150)
                            else:
                                st.error(f"❌ Decryption failed: {result['error']}")
                    else:
                        st.warning("⚠️ Please fill all fields")
        
        with col2:
            st.warning("""
            **⚠️ Important:**
            - Use same algorithm as encryption
            - All parameters required
            - Password must match
            """)
    
    else:  # Hash mode
        st.header("🔨 Hash Data")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            data_input = st.text_area("Enter data to hash", height=150, key="hash_data")
            hash_algo = st.selectbox("Hash Algorithm", ["SHA-256", "SHA-512", "SHA3-256", "BLAKE2b"])
            
            if st.button("🔨 Generate Hash", key="hash_btn"):
                if data_input:
                    hash_result = SecureEncryption.hash_data(data_input, hash_algo)
                    st.success("✅ Hash generated!")
                    st.subheader(f"📝 {hash_algo} Hash")
                    st.code(hash_result, language=None)
                    
                    st.info(f"📏 Hash length: {len(hash_result)} characters")
                else:
                    st.warning("⚠️ Please enter data to hash")
        
        with col2:
            st.info("""
            **ℹ️ About Hashing:**
            - One-way function
            - Cannot be reversed
            - Used for integrity verification
            - Same input = Same hash
            """)

if __name__ == "__main__":
    main()