
"""
AudioCrypt - A secure steganography tool for hiding encrypted messages in WAV files
GUI-based application using AES encryption and LSB (Least Significant Bit) steganography
"""

import os
import sys
import struct
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import soundfile as sf
import numpy as np


class AudioCrypt:
    """Main class for audio steganography operations"""

    MAGIC_HEADER = b"ACRYPT"  # Magic header to identify our hidden data
    SALT_SIZE = 16
    IV_SIZE = 16

    def __init__(self):
        self.backend = default_backend()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))

    def _encrypt_message(self, message: str, password: str) -> tuple:
        """Encrypt message using AES-256-CBC"""
        # Generate random salt and IV
        salt = os.urandom(self.SALT_SIZE)
        iv = os.urandom(self.IV_SIZE)

        # Derive key from password
        key = self._derive_key(password, salt)

        # Pad message to multiple of 16 bytes (PKCS7 padding)
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_message) + encryptor.finalize()

        return salt, iv, encrypted

    def _decrypt_message(self, salt: bytes, iv: bytes, encrypted_data: bytes, password: str) -> str:
        """Decrypt message using AES-256-CBC"""
        # Derive key from password
        key = self._derive_key(password, salt)

        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length]

        return message.decode('utf-8')

    def _read_audio_file(self, filename: str, progress_callback=None) -> tuple:
        """Read audio file and return audio samples and parameters"""
        try:
            data, samplerate = sf.read(filename, always_2d=True)
            if data.size == 0:
                raise ValueError("Audio file contains zero frames")

            if progress_callback:
                progress_callback(20)

            samples = (data * (2 ** 15 - 1)).astype(np.int16).flatten()

            if progress_callback:
                progress_callback(40)

            frames = data.shape[0]
            channels = data.shape[1]
            sample_width = 2  # int16
            frame_rate = samplerate

            if progress_callback:
                progress_callback(60)

            return samples.tolist(), (frames, sample_width, frame_rate, channels)
        except Exception as e:
            raise Exception(f"Error reading audio file: {str(e)}")

    def _write_audio_file(self, filename: str, samples: list, params: tuple, progress_callback=None):
        """Write samples to audio file"""
        frames, sample_width, frame_rate, channels = params

        try:
            data = np.array(samples, dtype=np.int16).reshape((frames, channels))
            sf.write(filename, data, frame_rate)

            if progress_callback:
                progress_callback(80)

            if progress_callback:
                progress_callback(100)
        except Exception as e:
            raise Exception(f"Error writing audio file: {str(e)}")

    def _int_to_bits(self, value: int, bits: int) -> list:
        """Convert integer to list of bits"""
        return [(value >> i) & 1 for i in range(bits)]

    def _bits_to_int(self, bits: list) -> int:
        """Convert list of bits to integer"""
        return sum(bit << i for i, bit in enumerate(bits))

    def _embed_data_lsb(self, samples: list, data: bytes, progress_callback=None) -> list:
        """Embed data into audio samples using LSB steganography"""
        # Convert data to bits
        data_bits = []
        for byte in data:
            data_bits.extend(self._int_to_bits(byte, 8))

        # Check if we have enough samples
        if len(data_bits) > len(samples):
            raise ValueError(
                f"Audio file too small to hide the message. Need {len(data_bits)} samples, have {len(samples)}")

        # Embed bits into LSB of samples
        modified_samples = samples.copy()
        total_bits = len(data_bits)

        for i, bit in enumerate(data_bits):
            # Clear LSB and set new bit
            modified_samples[i] = (modified_samples[i] & ~1) | bit

            if progress_callback and i % (total_bits // 10) == 0:
                progress = 60 + (i / total_bits) * 20
                progress_callback(progress)

        return modified_samples

    def _extract_data_lsb(self, samples: list, data_length: int, progress_callback=None) -> bytes:
        """Extract data from audio samples using LSB steganography"""
        # Extract bits from LSB
        extracted_bits = []
        total_bits = data_length * 8

        for i in range(total_bits):
            if i >= len(samples):
                raise ValueError("Unexpected end of audio data")
            extracted_bits.append(samples[i] & 1)

            if progress_callback and i % (total_bits // 10) == 0:
                progress = 60 + (i / total_bits) * 30
                progress_callback(progress)

        # Convert bits to bytes
        extracted_data = []
        for i in range(0, len(extracted_bits), 8):
            byte_bits = extracted_bits[i:i + 8]
            extracted_data.append(self._bits_to_int(byte_bits))

        return bytes(extracted_data)

    def encode(self, input_audio: str, output_audio: str, message: str, password: str, progress_callback=None):
        """Encode message into audio file"""
        try:
            if progress_callback:
                progress_callback(10)

            # Read input audio file
            samples, params = self._read_audio_file(input_audio, progress_callback)

            # Encrypt message
            salt, iv, encrypted_message = self._encrypt_message(message, password)

            # Create payload: MAGIC_HEADER + salt + iv + encrypted_length + encrypted_message
            encrypted_length = len(encrypted_message)
            payload = (self.MAGIC_HEADER +
                       salt +
                       iv +
                       struct.pack('<I', encrypted_length) +
                       encrypted_message)

            # Embed payload into audio samples
            modified_samples = self._embed_data_lsb(samples, payload, progress_callback)

            # Write output audio file
            self._write_audio_file(output_audio, modified_samples, params, progress_callback)

            return True, "Message successfully encoded"

        except Exception as e:
            return False, str(e)

    def decode(self, input_audio: str, password: str, progress_callback=None) -> tuple:
        """Decode message from audio file"""
        try:
            if progress_callback:
                progress_callback(10)

            # Read input audio file
            samples, _ = self._read_audio_file(input_audio, progress_callback)

            # Extract magic header
            header_data = self._extract_data_lsb(samples, len(self.MAGIC_HEADER), progress_callback)
            if header_data != self.MAGIC_HEADER:
                return False, "No hidden message found or invalid format"

            # Extract salt, IV, and encrypted length
            offset = len(self.MAGIC_HEADER) * 8
            salt_samples = samples[offset:offset + self.SALT_SIZE * 8]
            salt = self._extract_data_lsb(salt_samples, self.SALT_SIZE)

            offset += self.SALT_SIZE * 8
            iv_samples = samples[offset:offset + self.IV_SIZE * 8]
            iv = self._extract_data_lsb(iv_samples, self.IV_SIZE)

            offset += self.IV_SIZE * 8
            length_samples = samples[offset:offset + 4 * 8]
            encrypted_length = struct.unpack('<I', self._extract_data_lsb(length_samples, 4))[0]

            # Extract encrypted message
            offset += 4 * 8
            encrypted_samples = samples[offset:offset + encrypted_length * 8]
            encrypted_message = self._extract_data_lsb(encrypted_samples, encrypted_length)

            if progress_callback:
                progress_callback(90)

            # Decrypt message
            try:
                decrypted_message = self._decrypt_message(salt, iv, encrypted_message, password)
                if progress_callback:
                    progress_callback(100)
                return True, decrypted_message
            except Exception:
                return False, "Incorrect password or corrupted data"

        except Exception as e:
            return False, f"Error decoding: {str(e)}"


class AudioCryptGUI:
    """Modern GUI interface for AudioCrypt using Tkinter"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 AudioCrypt - Audio Steganography Tool")
        self.root.geometry("800x700")
        self.root.minsize(750, 650)
        self.root.configure(bg='#f0f0f0')

        # Set icon and styling
        self.setup_styling()

        self.audio_crypt = AudioCrypt()
        self.setup_gui()

        # Center window on screen
        self.center_window()

    def setup_styling(self):
        """Setup light theme styling for the GUI"""
        style = ttk.Style()

        # Configure light theme colors (white background, black text)
        self.root.configure(bg='#ffffff')
        style.theme_use('clam')

        # Configure custom light styles with black fonts
        style.configure('TFrame', background='#ffffff')
        style.configure('TLabel', background='#ffffff', foreground='#000000')
        style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'), foreground='#000000', background='#ffffff')
        style.configure('Heading.TLabel', font=('Helvetica', 11, 'bold'), foreground='#333333', background='#ffffff')
        style.configure('Info.TLabel', font=('Helvetica', 9), foreground='#555555', background='#ffffff')
        style.configure('Action.TButton', font=('Helvetica', 10, 'bold'), background='#f0f0f0', foreground='#000000')
        style.map('Action.TButton',
                  background=[('active', '#e0e0e0')],
                  foreground=[('active', '#000000')])

        # Configure notebook style
        style.configure('TNotebook.Tab', padding=[20, 10], background='#f0f0f0', foreground='#000000')
        style.configure('TNotebook', tabposition='n')

        # Configure scrolledtext widget for light theme
        self.root.option_add('*TScrolledText.background', '#ffffff')
        self.root.option_add('*TScrolledText.foreground', '#000000')
        self.root.option_add('*TScrolledText.insertBackground', '#000000')
        self.root.option_add('*TScrolledText.selectBackground', '#c0c0c0')
        self.root.option_add('*TScrolledText.selectForeground', '#000000')

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f'+{x}+{y}')

    def setup_gui(self):
        """Setup the main GUI components"""
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=20, pady=(20, 10))

        title_label = ttk.Label(header_frame, text="🔒 AudioCrypt", style='Title.TLabel')
        title_label.pack()

        subtitle_label = ttk.Label(header_frame, text="Secure Audio Steganography Tool", style='Info.TLabel')
        subtitle_label.pack()

        # Main content frame
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill='both', expand=True, padx=20, pady=10)

        # Main notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill='both', expand=True)

        # Encode tab
        encode_frame = ttk.Frame(self.notebook)
        self.notebook.add(encode_frame, text="🔐 Hide Message")
        self.setup_encode_tab(encode_frame)

        # Decode tab
        decode_frame = ttk.Frame(self.notebook)
        self.notebook.add(decode_frame, text="🔍 Extract Message")
        self.setup_decode_tab(decode_frame)

        # About tab
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="ℹ️ About")
        self.setup_about_tab(about_frame)

        # Status bar
        self.setup_status_bar()

    def setup_encode_tab(self, parent):
        """Setup the encode tab with modern design"""
        # Main frame with padding
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Input file section
        input_section = ttk.LabelFrame(main_frame, text="📁 Select Input Audio File", padding=15)
        input_section.pack(fill='x', pady=(0, 15))

        ttk.Label(input_section, text="Choose a WAV audio file to hide your message in:", style='Info.TLabel').pack(
            anchor='w', pady=(0, 10))

        input_frame = ttk.Frame(input_section)
        input_frame.pack(fill='x')
        self.input_wav_var = tk.StringVar()
        input_entry = ttk.Entry(input_frame, textvariable=self.input_wav_var, font=('Helvetica', 10))
        input_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ttk.Button(input_frame, text="📂 Browse", command=self.browse_input_file).pack(side='right')

        # Output file section
        output_section = ttk.LabelFrame(main_frame, text="💾 Save Encoded Audio As", padding=15)
        output_section.pack(fill='x', pady=(0, 15))

        ttk.Label(output_section, text="Choose where to save the audio file with hidden message:",
                  style='Info.TLabel').pack(anchor='w', pady=(0, 10))

        output_frame = ttk.Frame(output_section)
        output_frame.pack(fill='x')
        self.output_wav_var = tk.StringVar()
        output_entry = ttk.Entry(output_frame, textvariable=self.output_wav_var, font=('Helvetica', 10))
        output_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ttk.Button(output_frame, text="💾 Browse", command=self.browse_output_file).pack(side='right')

        # Message section
        message_section = ttk.LabelFrame(main_frame, text="✉️ Secret Message", padding=15)
        message_section.pack(fill='both', expand=True, pady=(0, 15))

        ttk.Label(message_section, text="Enter your secret message (will be encrypted):", style='Info.TLabel').pack(
            anchor='w', pady=(0, 10))

        text_frame = ttk.Frame(message_section)
        text_frame.pack(fill='both', expand=True)

        self.message_text = scrolledtext.ScrolledText(text_frame, height=8, font=('Consolas', 10), wrap='word')
        self.message_text.pack(fill='both', expand=True)

        # Character counter
        self.char_count_var = tk.StringVar(value="Characters: 0")
        ttk.Label(message_section, textvariable=self.char_count_var, style='Info.TLabel').pack(anchor='e', pady=(5, 0))
        self.message_text.bind('<KeyRelease>', self.update_char_count)

        # Password section
        password_section = ttk.LabelFrame(main_frame, text="🔑 Encryption Password", padding=15)
        password_section.pack(fill='x', pady=(0, 15))

        ttk.Label(password_section, text="Enter a strong password to encrypt your message:", style='Info.TLabel').pack(
            anchor='w', pady=(0, 10))

        password_frame = ttk.Frame(password_section)
        password_frame.pack(fill='x')

        self.encode_password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.encode_password_var, show='*',
                                   font=('Helvetica', 10))
        password_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))

        self.show_password_var = tk.BooleanVar()
        show_cb = ttk.Checkbutton(password_frame, text="Show", variable=self.show_password_var,
                                  command=lambda: self.toggle_password_visibility(password_entry))
        show_cb.pack(side='right')

        # Progress bar
        self.encode_progress = Progressbar(main_frame, mode='determinate')
        self.encode_progress.pack(fill='x', pady=(0, 15))

        # Encode button
        encode_btn = ttk.Button(main_frame, text="🔐 Hide Message in Audio", command=self.encode_message_threaded,
                                style='Action.TButton')
        encode_btn.pack(pady=(0, 10))

    def setup_decode_tab(self, parent):
        """Setup the decode tab with modern design"""
        # Main frame with padding
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Input file section
        input_section = ttk.LabelFrame(main_frame, text="📁 Select Encoded Audio File", padding=15)
        input_section.pack(fill='x', pady=(0, 15))

        ttk.Label(input_section, text="Choose a WAV audio file that contains a hidden message:",
                  style='Info.TLabel').pack(anchor='w', pady=(0, 10))

        decode_input_frame = ttk.Frame(input_section)
        decode_input_frame.pack(fill='x')
        self.decode_input_var = tk.StringVar()
        decode_input_entry = ttk.Entry(decode_input_frame, textvariable=self.decode_input_var, font=('Helvetica', 10))
        decode_input_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ttk.Button(decode_input_frame, text="📂 Browse", command=self.browse_decode_file).pack(side='right')

        # Password section
        decode_password_section = ttk.LabelFrame(main_frame, text="🔑 Decryption Password", padding=15)
        decode_password_section.pack(fill='x', pady=(0, 15))

        ttk.Label(decode_password_section, text="Enter the password used to encrypt the message:",
                  style='Info.TLabel').pack(anchor='w', pady=(0, 10))

        decode_password_frame = ttk.Frame(decode_password_section)
        decode_password_frame.pack(fill='x')

        self.decode_password_var = tk.StringVar()
        decode_password_entry = ttk.Entry(decode_password_frame, textvariable=self.decode_password_var, show='*',
                                          font=('Helvetica', 10))
        decode_password_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))

        self.show_decode_password_var = tk.BooleanVar()
        show_decode_cb = ttk.Checkbutton(decode_password_frame, text="Show", variable=self.show_decode_password_var,
                                         command=lambda: self.toggle_password_visibility(decode_password_entry))
        show_decode_cb.pack(side='right')

        # Progress bar
        self.decode_progress = Progressbar(main_frame, mode='determinate')
        self.decode_progress.pack(fill='x', pady=(0, 15))

        # Decode button
        decode_btn = ttk.Button(main_frame, text="🔍 Extract Hidden Message", command=self.decode_message_threaded,
                                style='Action.TButton')
        decode_btn.pack(pady=(0, 15))

        # Results section
        result_section = ttk.LabelFrame(main_frame, text="📝 Extracted Message", padding=15)
        result_section.pack(fill='both', expand=True)

        self.decoded_text = scrolledtext.ScrolledText(result_section, height=10, font=('Consolas', 10), wrap='word',
                                                      state='disabled')
        self.decoded_text.pack(fill='both', expand=True, pady=(0, 10))

        # Action buttons for decoded message
        button_frame = ttk.Frame(result_section)
        button_frame.pack(fill='x')

        ttk.Button(button_frame, text="📋 Copy to Clipboard", command=self.copy_decoded_message).pack(side='left',
                                                                                                     padx=(0, 10))
        ttk.Button(button_frame, text="💾 Save to File", command=self.save_decoded_message).pack(side='left')
        ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_decoded_message).pack(side='right')

    def setup_about_tab(self, parent):
        """Setup the about tab with tool information"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)

        # Title
        title_label = ttk.Label(main_frame, text="🔒 AudioCrypt", style='Title.TLabel')
        title_label.pack(pady=(0, 10))

        # Description
        desc_text = """AudioCrypt is a secure audio steganography tool that allows you to hide encrypted text messages inside WAV audio files using advanced cryptographic techniques.

🔐 Security Features:
• AES-256-CBC encryption with PBKDF2 key derivation
• 100,000 iterations for strong password protection
• Random salt and initialization vector for each operation
• PKCS7 padding for secure block alignment

🎵 Steganography Features:
• LSB (Least Significant Bit) modification technique
• Minimal impact on audio quality
• Supports all standard WAV formats (8-bit, 16-bit, 32-bit)
• Automatic capacity checking

💡 How to Use:
1. Hide Message: Select a WAV file, enter your secret message and password
2. Extract Message: Select the encoded WAV file and enter the correct password
3. Your message will be securely encrypted and hidden in the audio

⚠️ Important Notes:
• Keep your password safe - it cannot be recovered if lost
• Only WAV format audio files are supported
• The original audio quality is preserved with minimal changes
• Larger messages require larger audio files"""

        text_widget = scrolledtext.ScrolledText(main_frame, wrap='word', font=('Helvetica', 10), state='disabled',
                                                height=20)
        text_widget.pack(fill='both', expand=True, pady=(0, 20))

        text_widget.config(state='normal')
        text_widget.insert('1.0', desc_text)
        text_widget.config(state='disabled')

        # Version info
        version_frame = ttk.Frame(main_frame)
        version_frame.pack(fill='x')
        ttk.Label(version_frame, text="Version 1.0 | Built with Python & Tkinter", style='Info.TLabel').pack()

    def setup_status_bar(self):
        """Setup status bar at the bottom"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill='x', side='bottom')

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.status_frame, textvariable=self.status_var, style='Info.TLabel')
        status_label.pack(side='left', padx=20, pady=5)

    def update_char_count(self, event=None):
        """Update character count for message"""
        text = self.message_text.get("1.0", tk.END).strip()
        count = len(text)
        self.char_count_var.set(f"Characters: {count}")

    def toggle_password_visibility(self, entry_widget):
        """Toggle password visibility"""
        if entry_widget.cget('show') == '*':
            entry_widget.config(show='')
        else:
            entry_widget.config(show='*')

    def update_status(self, message):
        """Update status bar message"""
        self.status_var.set(message)
        self.root.update_idletasks()

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select Input WAV File",
            filetypes=[("WAV Audio Files", "*.wav"), ("All Files", "*.*")],
            defaultextension=".wav"
        )
        if filename:
            self.input_wav_var.set(filename)
            self.update_status(f"Input file selected: {os.path.basename(filename)}")

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(
            title="Save Encoded WAV File As",
            defaultextension=".wav",
            filetypes=[("WAV Audio Files", "*.wav"), ("All Files", "*.*")]
        )
        if filename:
            self.output_wav_var.set(filename)
            self.update_status(f"Output file set: {os.path.basename(filename)}")

    def browse_decode_file(self):
        filename = filedialog.askopenfilename(
            title="Select Encoded WAV File",
            filetypes=[("WAV Audio Files", "*.wav"), ("All Files", "*.*")],
            defaultextension=".wav"
        )
        if filename:
            self.decode_input_var.set(filename)
            self.update_status(f"Decode file selected: {os.path.basename(filename)}")

    def encode_message_threaded(self):
        """Encode message in a separate thread"""
        thread = threading.Thread(target=self.encode_message, daemon=True)
        thread.start()

    def decode_message_threaded(self):
        """Decode message in a separate thread"""
        thread = threading.Thread(target=self.decode_message, daemon=True)
        thread.start()

    def encode_message(self):
        """Encode message into audio file"""
        input_file = self.input_wav_var.get().strip()
        output_file = self.output_wav_var.get().strip()
        message = self.message_text.get("1.0", tk.END).strip()
        password = self.encode_password_var.get()

        # Validation
        if not all([input_file, output_file, message, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return

        if not os.path.exists(input_file):
            messagebox.showerror("Error", "Input file does not exist")
            return

        if len(password) < 6:
            messagebox.showwarning("Warning", "Password should be at least 6 characters long for better security")

        # Reset progress bar
        self.encode_progress['value'] = 0
        self.update_status("Encoding message...")

        def progress_callback(value):
            self.encode_progress['value'] = value
            self.root.update_idletasks()

        try:
            success, result = self.audio_crypt.encode(input_file, output_file, message, password, progress_callback)

            if success:
                self.update_status("Encoding completed successfully")
                messagebox.showinfo("Success", f"{result}\n\nFile saved: {os.path.basename(output_file)}")

                # Ask if user wants to open file location
                if messagebox.askyesno("Open Location", "Would you like to open the file location?"):
                    if sys.platform.startswith('win'):
                        os.startfile(os.path.dirname(output_file))
                    elif sys.platform.startswith('darwin'):
                        os.system(f'open "{os.path.dirname(output_file)}"')
                    else:  # Linux
                        os.system(f'xdg-open "{os.path.dirname(output_file)}"')
            else:
                self.update_status("Encoding failed")
                messagebox.showerror("Error", result)

        except Exception as e:
            self.update_status("Encoding failed")
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")

        finally:
            self.encode_progress['value'] = 0

    def decode_message(self):
        """Decode message from audio file"""
        input_file = self.decode_input_var.get().strip()
        password = self.decode_password_var.get()

        # Validation
        if not all([input_file, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return

        if not os.path.exists(input_file):
            messagebox.showerror("Error", "Input file does not exist")
            return

        # Reset progress bar
        self.decode_progress['value'] = 0
        self.update_status("Extracting hidden message...")

        def progress_callback(value):
            self.decode_progress['value'] = value
            self.root.update_idletasks()

        try:
            success, result = self.audio_crypt.decode(input_file, password, progress_callback)

            # Update decoded text area
            self.decoded_text.config(state='normal')
            self.decoded_text.delete("1.0", tk.END)

            if success:
                self.decoded_text.insert("1.0", result)
                self.update_status("Message extracted successfully")
                messagebox.showinfo("Success", "Hidden message extracted successfully!")
            else:
                self.decoded_text.insert("1.0", f"❌ ERROR: {result}")
                self.update_status("Extraction failed")

                # Provide helpful error messages
                if "Incorrect password" in result:
                    messagebox.showerror("Incorrect Password",
                                         "The password is incorrect or the audio file is corrupted.\n\n"
                                         "Please check:\n"
                                         "• Password spelling and case sensitivity\n"
                                         "• That this file contains a hidden message\n"
                                         "• That the file hasn't been modified")
                elif "No hidden message" in result:
                    messagebox.showerror("No Hidden Message",
                                         "This audio file doesn't appear to contain a hidden message.\n\n"
                                         "Make sure you selected the correct file that was created with AudioCrypt.")
                else:
                    messagebox.showerror("Error", result)

            self.decoded_text.config(state='disabled')

        except Exception as e:
            self.update_status("Extraction failed")
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")

            self.decoded_text.config(state='normal')
            self.decoded_text.delete("1.0", tk.END)
            self.decoded_text.insert("1.0", f"❌ ERROR: {str(e)}")
            self.decoded_text.config(state='disabled')

        finally:
            self.decode_progress['value'] = 0

    def copy_decoded_message(self):
        """Copy decoded message to clipboard"""
        text = self.decoded_text.get("1.0", tk.END).strip()
        if text and not text.startswith("❌ ERROR"):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            self.update_status("Message copied to clipboard")
            messagebox.showinfo("Copied", "Message copied to clipboard!")
        else:
            messagebox.showwarning("No Message", "No message to copy or message extraction failed")

    def save_decoded_message(self):
        """Save decoded message to file"""
        text = self.decoded_text.get("1.0", tk.END).strip()
        if text and not text.startswith("❌ ERROR"):
            filename = filedialog.asksaveasfilename(
                title="Save Decoded Message",
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("All Files", "*.*")
                ]
            )

            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.update_status(f"Message saved to {os.path.basename(filename)}")
                    messagebox.showinfo("Saved", f"Message saved to:\n{filename}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file:\n{str(e)}")
        else:
            messagebox.showwarning("No Message", "No message to save or message extraction failed")

    def clear_decoded_message(self):
        """Clear the decoded message area"""
        self.decoded_text.config(state='normal')
        self.decoded_text.delete("1.0", tk.END)
        self.decoded_text.config(state='disabled')
        self.update_status("Decoded message cleared")

    def run(self):
        """Run the GUI application"""
        # Set up window close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start the GUI event loop
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()

    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit AudioCrypt?"):
            self.root.quit()
            self.root.destroy()


class AudioCryptCLI:
    """Command Line Interface for AudioCrypt (optional)"""

    def __init__(self):
        self.audio_crypt = AudioCrypt()

    def run_cli(self, args):
        """Run CLI version if needed"""
        import argparse

        parser = argparse.ArgumentParser(description="AudioCrypt - Hide encrypted messages in WAV files")
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Encode command
        encode_parser = subparsers.add_parser('encode', help='Encode message into WAV file')
        encode_parser.add_argument('-i', '--input', required=True, help='Input WAV file')
        encode_parser.add_argument('-o', '--output', required=True, help='Output WAV file')
        encode_parser.add_argument('-m', '--message', required=True, help='Secret message to hide')
        encode_parser.add_argument('-p', '--password', required=True, help='Password for encryption')

        # Decode command
        decode_parser = subparsers.add_parser('decode', help='Decode message from WAV file')
        decode_parser.add_argument('-i', '--input', required=True, help='Input stego WAV file')
        decode_parser.add_argument('-p', '--password', required=True, help='Password for decryption')

        parsed_args = parser.parse_args(args)

        if not parsed_args.command:
            print("No command specified. Use --help for usage information.")
            print("Launching GUI interface...")
            return False

        if parsed_args.command == 'encode':
            if not os.path.exists(parsed_args.input):
                print(f"Error: Input file '{parsed_args.input}' not found")
                return True

            print("Encoding message...")
            success, result = self.audio_crypt.encode(
                parsed_args.input,
                parsed_args.output,
                parsed_args.message,
                parsed_args.password
            )

            if success:
                print(f"✅ Success: {result}")
                print(f"📁 Hidden message saved to: {parsed_args.output}")
            else:
                print(f"❌ Error: {result}")

            return True

        elif parsed_args.command == 'decode':
            if not os.path.exists(parsed_args.input):
                print(f"Error: Input file '{parsed_args.input}' not found")
                return True

            print("Decoding message...")
            success, result = self.audio_crypt.decode(parsed_args.input, parsed_args.password)

            if success:
                print("✅ Decoded message:")
                print("-" * 50)
                print(result)
                print("-" * 50)
            else:
                print(f"❌ Error: {result}")

            return True

        return False


def main():
    """Main entry point"""
    # Check if running with command line arguments
    if len(sys.argv) > 1:
        cli = AudioCryptCLI()
        if cli.run_cli(sys.argv[1:]):
            return

    # Check for required dependencies
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        import tkinter as tk
    except ImportError as e:
        print("❌ Missing required dependencies!")
        print("Please install required packages:")
        print("pip install cryptography")
        if 'tkinter' in str(e):
            print(
                "Note: tkinter should be included with Python. If missing, please reinstall Python with tkinter support.")
        sys.exit(1)

    # Launch GUI
    try:
        print("🔒 Starting AudioCrypt GUI...")
        app = AudioCryptGUI()
        app.run()
    except Exception as e:
        print(f"❌ Error starting GUI: {str(e)}")
        print("Try running with CLI arguments instead:")
        print("python audiocrypt.py encode -i input.wav -o output.wav -m 'message' -p 'password'")
        print("python audiocrypt.py decode -i encoded.wav -p 'password'")


if __name__ == "__main__":
    main()