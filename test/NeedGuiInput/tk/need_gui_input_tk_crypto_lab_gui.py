import base64
import os
import tkinter as tk
from tkinter import ttk, messagebox

import hashlib

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ---------------- Hash Tab ---------------- #
def compute_hash():
    data = hash_input_text.get("1.0", tk.END).rstrip("\n")
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    hash_output_var.set(digest)


def clear_hash():
    hash_input_text.delete("1.0", tk.END)
    hash_output_var.set("")


# ---------------- Symmetric Tab ---------------- #
def ensure_crypto():
    if not HAS_CRYPTO:
        messagebox.showerror(
            "Missing dependency",
            "cryptography 패키지가 설치되어 있지 않습니다.\n"
            "pip install cryptography 로 설치 후 다시 시도하세요.",
        )
        return False
    return True


def generate_key():
    if not ensure_crypto():
        return
    key = os.urandom(32)
    sym_key_var.set(key.hex())


def encrypt_message():
    if not ensure_crypto():
        return
    plaintext = sym_input_text.get("1.0", tk.END).rstrip("\n")
    if not plaintext:
        messagebox.showwarning("입력 필요", "평문을 입력하세요.")
        return

    key_hex = sym_key_var.get().strip()
    try:
        key = bytes.fromhex(key_hex) if key_hex else os.urandom(32)
    except ValueError:
        messagebox.showerror("키 오류", "키는 32바이트(64 hex)여야 합니다.")
        return

    if len(key) != 32:
        messagebox.showerror("키 길이", "키는 32바이트(256비트)여야 합니다.")
        return

    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    payload = base64.b64encode(iv + ciphertext).decode("ascii")
    sym_output_var.set(payload)
    sym_status_var.set("암호화 완료 (IV+CT base64)")
    if not key_hex:
        sym_key_var.set(key.hex())


def decrypt_message():
    if not ensure_crypto():
        return
    data_b64 = sym_output_var.get().strip()
    if not data_b64:
        messagebox.showwarning("입력 필요", "복호화할 데이터를 입력하세요.")
        return
    try:
        raw = base64.b64decode(data_b64)
    except Exception:
        messagebox.showerror("데이터 오류", "Base64 디코딩에 실패했습니다.")
        return
    if len(raw) < 16:
        messagebox.showerror("데이터 오류", "IV와 암호문 형식이 올바르지 않습니다.")
        return

    key_hex = sym_key_var.get().strip()
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        messagebox.showerror("키 오류", "키는 32바이트(64 hex)여야 합니다.")
        return
    if len(key) != 32:
        messagebox.showerror("키 길이", "키는 32바이트(256비트)여야 합니다.")
        return

    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        messagebox.showerror("복호화 오류", "패딩 제거에 실패했습니다. 키 또는 데이터가 잘못되었습니다.")
        return
    sym_input_text.delete("1.0", tk.END)
    sym_input_text.insert(tk.END, plaintext.decode("utf-8", errors="replace"))
    sym_status_var.set("복호화 완료")


# ---------------- Public Key Tab ---------------- #
RSA_KEY_PAIR = None


def ensure_keypair():
    global RSA_KEY_PAIR
    if not ensure_crypto():
        return False
    if RSA_KEY_PAIR is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        RSA_KEY_PAIR = private_key
        pk_status_var.set("새 RSA 키쌍 생성 완료 (1024비트)")
    return True


def regenerate_keypair():
    global RSA_KEY_PAIR
    if not ensure_crypto():
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    RSA_KEY_PAIR = private_key
    pk_signature_var.set("")
    pk_status_var.set("새 RSA 키쌍 생성 완료 (1024비트)")


def sign_message():
    if not ensure_keypair():
        return
    message = pk_input_text.get("1.0", tk.END).rstrip("\n")
    if not message:
        messagebox.showwarning("입력 필요", "서명할 메시지를 입력하세요.")
        return
    private_key = RSA_KEY_PAIR
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    pk_signature_var.set(base64.b64encode(signature).decode("ascii"))
    pk_status_var.set("서명 생성 완료")


def verify_signature():
    if not ensure_keypair():
        return
    message = pk_input_text.get("1.0", tk.END).rstrip("\n")
    signature_b64 = pk_signature_var.get().strip()
    if not message or not signature_b64:
        messagebox.showwarning("입력 필요", "메시지와 서명 값을 모두 입력하세요.")
        return
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        messagebox.showerror("서명 오류", "Base64 디코딩에 실패했습니다.")
        return
    public_key = RSA_KEY_PAIR.public_key()
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception:
        pk_status_var.set("서명 검증 실패")
    else:
        pk_status_var.set("서명 검증 성공")


# ---------------- GUI Construction ---------------- #
root = tk.Tk()
root.title("Crypto GUI Lab")
root.geometry("640x480")

main = ttk.Frame(root, padding=12)
main.pack(fill=tk.BOTH, expand=True)

notebook = ttk.Notebook(main)
notebook.pack(fill=tk.BOTH, expand=True)

# Hash tab
hash_tab = ttk.Frame(notebook)
notebook.add(hash_tab, text="Hash")

ttk.Label(hash_tab, text="Input Message:").pack(anchor="w")
hash_input_text = tk.Text(hash_tab, height=6, wrap="word")
hash_input_text.pack(fill=tk.BOTH, expand=True)

hash_btn_row = ttk.Frame(hash_tab)
hash_btn_row.pack(fill=tk.X, pady=6)

ttk.Button(hash_btn_row, text="Compute SHA-256", command=compute_hash).pack(
    side=tk.LEFT, padx=4
)
ttk.Button(hash_btn_row, text="Clear", command=clear_hash).pack(side=tk.LEFT, padx=4)

hash_output_var = tk.StringVar()
ttk.Label(hash_tab, text="Digest (hex):").pack(anchor="w")
hash_output_entry = ttk.Entry(hash_tab, textvariable=hash_output_var, state="readonly")
hash_output_entry.pack(fill=tk.X)

# Symmetric tab
sym_tab = ttk.Frame(notebook)
notebook.add(sym_tab, text="Symmetric")

sym_status_var = tk.StringVar(value="AES-256/CBC with PKCS7 padding")
ttk.Label(sym_tab, textvariable=sym_status_var, foreground="#555555").pack(
    anchor="w"
)

key_row = ttk.Frame(sym_tab)
key_row.pack(fill=tk.X, pady=4)
ttk.Label(key_row, text="Key (hex, 32 bytes):").pack(side=tk.LEFT)
sym_key_var = tk.StringVar()
key_entry = ttk.Entry(key_row, textvariable=sym_key_var)
key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
ttk.Button(key_row, text="Generate", command=generate_key).pack(side=tk.LEFT)

ttk.Label(sym_tab, text="Plaintext:").pack(anchor="w")
sym_input_text = tk.Text(sym_tab, height=6, wrap="word")
sym_input_text.pack(fill=tk.BOTH, expand=True)

sym_btn_row = ttk.Frame(sym_tab)
sym_btn_row.pack(fill=tk.X, pady=6)

ttk.Button(sym_btn_row, text="Encrypt", command=encrypt_message).pack(
    side=tk.LEFT, padx=4
)
ttk.Button(sym_btn_row, text="Decrypt", command=decrypt_message).pack(
    side=tk.LEFT, padx=4
)

sym_output_var = tk.StringVar()
ttk.Label(sym_tab, text="IV + Ciphertext (base64):").pack(anchor="w")
sym_output_entry = ttk.Entry(sym_tab, textvariable=sym_output_var)
sym_output_entry.pack(fill=tk.X)

# Public key tab
pk_tab = ttk.Frame(notebook)
notebook.add(pk_tab, text="Public Key")

pk_status_var = tk.StringVar(value="RSA-PSS with SHA-256")
ttk.Label(pk_tab, textvariable=pk_status_var, foreground="#555555").pack(anchor="w")

pk_btn_row = ttk.Frame(pk_tab)
pk_btn_row.pack(fill=tk.X, pady=4)
ttk.Button(pk_btn_row, text="Regenerate Key", command=regenerate_keypair).pack(
    side=tk.LEFT, padx=4
)

pk_input_label = ttk.Label(pk_tab, text="Message:")
pk_input_label.pack(anchor="w")

pk_input_text = tk.Text(pk_tab, height=6, wrap="word")
pk_input_text.pack(fill=tk.BOTH, expand=True)

pk_action_row = ttk.Frame(pk_tab)
pk_action_row.pack(fill=tk.X, pady=6)

ttk.Button(pk_action_row, text="Sign", command=sign_message).pack(
    side=tk.LEFT, padx=4
)
ttk.Button(pk_action_row, text="Verify", command=verify_signature).pack(
    side=tk.LEFT, padx=4
)

pk_signature_var = tk.StringVar()
ttk.Label(pk_tab, text="Signature (base64):").pack(anchor="w")
pk_signature_entry = ttk.Entry(pk_tab, textvariable=pk_signature_var)
pk_signature_entry.pack(fill=tk.X)

if not HAS_CRYPTO:
    sym_status_var.set("cryptography 패키지가 없어 AES/RSA 기능이 비활성화됩니다.")
    pk_status_var.set("cryptography 패키지가 없어 RSA 기능이 비활성화됩니다.")

root.mainloop()
