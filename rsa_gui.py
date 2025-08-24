import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from rsa_core import generate_keys, encrypt, decrypt, save_keys, load_keys

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption Tool")
        self.root.geometry("800x700")
        self.root.config(bg="#f5f5f5")

        self.pub_key = None
        self.priv_key = None

        self.font = ("Helvetica", 12)

        # Top-level frame to hold everything
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Frame: Key Management
        key_frame = ttk.LabelFrame(main_frame, text="Key Management", padding="10")
        key_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(key_frame, text="Generate Keys", width=18, command=self.generate_keys).pack(side="left", padx=5, pady=5)
        ttk.Button(key_frame, text="Save Keys", width=18, command=self.save_keys).pack(side="left", padx=5, pady=5)
        ttk.Button(key_frame, text="Load Keys", width=18, command=self.load_keys).pack(side="left", padx=5, pady=5)

        # Input Text Frame
        input_frame = ttk.LabelFrame(main_frame, text="Input Text", padding="10")
        input_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.input_text = tk.Text(input_frame, height=5, font=self.font, wrap="word")
        self.input_text.pack(fill="both", expand=True)

        # Encrypted Text Frame
        encrypted_frame = ttk.LabelFrame(main_frame, text="Encrypted Output", padding="10")
        encrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.encrypted_text = tk.Text(encrypted_frame, height=5, font=self.font, wrap="word")
        self.encrypted_text.pack(fill="both", expand=True)

        # Decrypted Text Frame
        decrypted_frame = ttk.LabelFrame(main_frame, text="Decrypted Output", padding="10")
        decrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.decrypted_text = tk.Text(decrypted_frame, height=5, font=self.font, wrap="word")
        self.decrypted_text.pack(fill="both", expand=True)

        # Frame: Operation Buttons
        op_frame = ttk.LabelFrame(main_frame, text="Operations", padding="10")
        op_frame.pack(fill="x", padx=5, pady=10)

        for label, cmd in [
            ("Encrypt", self.encrypt_text),
            ("Decrypt", self.decrypt_text),
            ("Encrypt Text File", self.encrypt_file),
            ("Decrypt Text File", self.decrypt_file),
            ("Clear All", self.clear_all),
        ]:
            ttk.Button(op_frame, text=label, width=18, command=cmd).pack(side="left", padx=5, pady=5)

    def generate_keys(self):
        self.pub_key, self.priv_key = generate_keys(bits=512)
        messagebox.showinfo("RSA", "Keys generated successfully!")

    def save_keys(self):
        if not self.pub_key or not self.priv_key:
            messagebox.showwarning("RSA", "Generate keys first!")
            return
        save_keys(self.pub_key, self.priv_key)
        messagebox.showinfo("RSA", "Keys saved to rsa_keys.json")

    def load_keys(self):
        try:
            self.pub_key, self.priv_key = load_keys()
            messagebox.showinfo("RSA", "Keys loaded successfully!")
        except Exception as e:
            messagebox.showerror("RSA", f"Error loading keys: {e}")

    def encrypt_text(self):
        if not self.pub_key:
            messagebox.showwarning("RSA", "Generate or load keys first!")
            return
        msg = self.input_text.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("RSA", "Enter some text to encrypt!")
            return
        cipher = encrypt(msg, self.pub_key)
        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, cipher)

    def decrypt_text(self):
        if not self.priv_key:
            messagebox.showwarning("RSA", "Generate or load keys first!")
            return
        cipher = self.encrypted_text.get("1.0", tk.END).strip()
        if not cipher:
            messagebox.showwarning("RSA", "Enter some text to decrypt!")
            return
        try:
            decrypted = decrypt(cipher, self.priv_key)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted)
        except Exception:
            messagebox.showerror("RSA", "Decryption failed! Invalid key or corrupted ciphertext.")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not file_path or not self.pub_key:
            return
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        encrypted = encrypt(content, self.pub_key)
        out_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if out_path:
            with open(out_path, 'w', encoding='utf-8') as file:
                file.write(encrypted)
            messagebox.showinfo("RSA", f"Encrypted content saved to {out_path}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not file_path or not self.priv_key:
            return
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        try:
            decrypted = decrypt(content, self.priv_key)
            out_path = filedialog.asksaveasfilename(defaultextension=".txt")
            if out_path:
                with open(out_path, 'w', encoding='utf-8') as file:
                    file.write(decrypted)
                messagebox.showinfo("RSA", f"Decrypted content saved to {out_path}")
        except Exception:
            messagebox.showerror("RSA", "Decryption failed! Invalid key or corrupted ciphertext.")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.encrypted_text.delete("1.0", tk.END)
        self.decrypted_text.delete("1.0", tk.END)

# Run the GUI app
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()
