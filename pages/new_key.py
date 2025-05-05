import tkinter as tk
from tkinter import ttk, filedialog
from pathlib import Path
import logging
import hashlib
import binascii
from PGPy import pgpy
from media import MediaDisplay
from key import KeyManager
from tkinter import messagebox

TEXT_WIDGET_HEIGHT = 10

DEFAULT_PUBKEY_EXTENSION = ".asc"
PUBKEY_FILE_TYPES = [("Public key files", f"*{DEFAULT_PUBKEY_EXTENSION}")]

METADATA_INFO = (
    "Fill your GPG public information.\n"
)

SCAN_PUB_KEY_INFO = (
    "On your Krux:\n"
    " 1. Load a key as usual.\n"
    " 2. Go to Wallet -> BIP85 -> GPG Key -> Index -> Create GPG Public Key.\n"
    " 3. Scan the QR Code exported by Krux containing the public key curve point.\n"
)
CERTIFY_INFO = (
    "To certify your key's UID, you need to self-sign it.\n"
    ' 1. On your Krux, chose "Yes" to scan and sign key\'s metadata from QR code below.\n'
    " 2. Scan the signature QR code exported by Krux.\n"
)

class NewKey(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg=controller.bg_color)  # Comment this to debug widget areas

        self.attributes_display = tk.Text(
            self,
            wrap="word",
            height=TEXT_WIDGET_HEIGHT,
            bg=self.controller.entry_bg,
            fg="lime",
            borderwidth=0,
            highlightthickness=0,
            padx=20,
            pady=10,
        )

        self.scan_buttons_frame = ttk.Frame(self)
        self.media_display = MediaDisplay(self, padding="10")

        # UID variables
        self.user_name = ""
        self.user_email = ""

        # Key variables
        self.key_manager = KeyManager()
        self.hex_key_material = None
        self.sig_data = None
        self.key = None

    def on_show(self):
        """Called when the frame is shown."""
        for widget in self.grid_slaves():
            widget.grid_forget()
        self.grid_rowconfigure(0, weight=1)  # Attributes and info
        self.grid_rowconfigure(1, weight=1, minsize=self.controller.font_size * 6)  # Entries
        self.grid_rowconfigure(2, weight=1, minsize=self.controller.font_size * 4)  # Buttons
        self.grid_rowconfigure(3, weight=2)  # Media/QR/camera
        self.grid_columnconfigure(0, weight=1)
        self.attributes_display.config(font=self.controller.dynamic_font_small)
        self.attributes_display.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        self.media_display.grid(row=3, column=0, sticky="nsew")
        self.media_display.load_default_image()

        self.collect_uid()


    def collect_uid(self):
        """Collect the UID from the user."""

        #If coming back from the scan buttons, hide them
        self.scan_buttons_frame.grid_forget()
        # Frame to hold the Name and email entries
        entry_frame = ttk.Frame(self)
        entry_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        entry_frame.rowconfigure(0, weight=1)
        entry_frame.rowconfigure(1, weight=1)
        entry_frame.columnconfigure(1, weight=1)

        # Name Label + Entry
        name_label = ttk.Label(entry_frame, text="Name:")
        name_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.name_entry = ttk.Entry(entry_frame, font=self.controller.dynamic_font)
        self.name_entry.insert(0, self.user_name)
        self.name_entry.grid(row=0, column=1, sticky="ew", padx=(5,10), pady=5)
        # email Label + Entry
        email_label = ttk.Label(entry_frame, text="email:")
        email_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.email_entry = ttk.Entry(entry_frame, font=self.controller.dynamic_font)
        self.email_entry.insert(0, self.user_email)
        self.email_entry.grid(row=1, column=1, sticky="ew", padx=(5,10), pady=5)
        self._update_attributes_display(METADATA_INFO)

        def load_entries():
            """Load the name and email from the entries."""
            self.user_name = self.name_entry.get()
            self.user_email = self.email_entry.get()
            if not self.user_name or not self.user_email:
                messagebox.showerror("Input Error", "Both name and email are required.")
                return
            entry_frame.grid_forget()
            self.rowconfigure(1, weight=0, minsize=0)  # Hide the entry slot
            buttons_frame.grid_forget()
            self.scan_raw_pubkey()

        # Create a frame for the buttons
        buttons_frame = ttk.Frame(self)
        buttons_frame.rowconfigure(0, weight=1)
        buttons_frame.columnconfigure(0, weight=1)
        buttons_frame.columnconfigure(1, weight=1)
        buttons_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        self.back_btn = ttk.Button(
            buttons_frame,
            text="Back",
            command=lambda: self.controller.show_frame("LoginPage")
        )
        self.back_btn.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

        load_uid_btn = ttk.Button(
            buttons_frame,
            text="Next",
            command=load_entries
        )
        load_uid_btn.grid(row=0, column=1, sticky="nsew", padx=10, pady=5)
        

    def scan_raw_pubkey(self):
            """Scan a raw public key from the camera."""
            self._update_attributes_display(SCAN_PUB_KEY_INFO)
            self.media_display.load_default_image()
            # Create a frame for the buttons
            self.scan_buttons_frame.columnconfigure(0, weight=1)
            self.scan_buttons_frame.columnconfigure(1, weight=1)
            self.scan_buttons_frame.rowconfigure(0, weight=1)
            self.scan_buttons_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

            # Create a back button
            self.back_btn = ttk.Button(self.scan_buttons_frame,
                                   text="Back",
                                   command=self.collect_uid)
            self.back_btn.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
            self.scan_button = ttk.Button(self.scan_buttons_frame,
                                text="Scan",
                                command=self.scan_qr)
            self.scan_button.grid(row=0, column=1, sticky="nsew",  padx=10, pady=5)

    def scan_qr(self, pub_certification=False):
        """Start the QR code scanning process."""
        self.scan_buttons_frame.grid_forget()
        self.media_display.start_scan()
        self.monitor_scan(pub_certification=pub_certification)

    def monitor_scan(self, pub_certification=False):
        """Checks for scanned QR code periodically."""
        if self.media_display.qr_found:
            self.media_display.stop_scan()
            if pub_certification:
                self._process_certification()
            else:
                self._process_pubkey()
        elif self.media_display.camera_running:
            # Schedule the next check
            self.after(100, lambda: self.monitor_scan(pub_certification=pub_certification))
        else:
            # Scan aborted, show scan button again
            if self.scan_button and not self.scan_button.winfo_ismapped():
                self.scan_buttons_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
            # If certifying, show QR code again
            if pub_certification:
                try:
                    self.media_display.export_qr_code_image(
                        hashlib.sha256(self.sig_data).hexdigest()
                    )
                except:
                    pass

    def _process_pubkey(self):
        """Process the scanned public key."""
        # Get the scanned data
        self.hex_key_material = self.media_display.qr_found
        self.media_display.qr_found = None
        self.sig_data = self.key_manager.create_key(
            self.user_name,
            self.user_email,
            self.hex_key_material,
        )
        self.media_display.export_qr_code_image(
            hashlib.sha256(self.sig_data).hexdigest()
        )
        self._scan_certification()


    def _scan_certification(self):
        self._update_attributes_display(CERTIFY_INFO)
        self.scan_buttons_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        # Redefine buttons
        self.back_btn = ttk.Button(self.scan_buttons_frame,
                                   text="Back",
                                   command=self.scan_raw_pubkey)
        self.back_btn.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
        self.scan_button = ttk.Button(self.scan_buttons_frame,
                            text="Scan",
                            command=lambda: self.scan_qr(pub_certification=True))
        self.scan_button.grid(row=0, column=1, sticky="nsew",  padx=10, pady=5)
        

    def _process_certification(self):
        """Process the scanned certification."""
        # Get the scanned data
        scanned_data = self.media_display.qr_found
        self.media_display.qr_found = None
        cert_bytes = binascii.a2b_base64(scanned_data)
        self.key_manager.inject_key(
            inject=cert_bytes,
            ext_sig_data=self.sig_data,
        )
        pubkey_str = str(self.key_manager.key.pubkey)
        uid_valid_sig = False
        try:
            pubkey, _ = pgpy.PGPKey.from_blob(pubkey_str)
            first_uid = next(iter(pubkey.userids), None)
            uid_valid_sig = bool(pubkey.verify(first_uid, first_uid.selfsig))
        except Exception as e:
            logging.error(f"Error verifying signature: {e}")
        
        self.scan_buttons_frame.grid_forget()
        
        if not uid_valid_sig:
            self._update_attributes_display(
                "Key verification failed."
            )
        else:
            self._update_attributes_display(
                "Key successfully certified.\n\n"
                f"Key fingerprint:\n{self.key_manager.key.fingerprint.__pretty__()}\n\n"
                "You can now save the key for later use, or load and use it to sign files right now."
            )
            self.pubkey_options_frame = ttk.Frame(self)
            self.pubkey_options_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
            self.pubkey_options_frame.columnconfigure(0, weight=1)
            self.pubkey_options_frame.columnconfigure(1, weight=1)
            self.pubkey_options_frame.rowconfigure(0, weight=1)

            self.save_btn = ttk.Button(self.pubkey_options_frame,
                                    text="Save Public Key",
                                    command=self.save_key)
            self.save_btn.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)
            self.back_btn = ttk.Button(self.pubkey_options_frame,
                                    text="Load Key",
                                    command=self._load_new_key)
            self.back_btn.grid(row=0, column=1, sticky="nsew", padx=10, pady=5)

    def save_key(self):
        """Save the key to a file."""
        initial_filename = f"{self.user_name}{DEFAULT_PUBKEY_EXTENSION}"
        save_path_str = filedialog.asksaveasfilename(
            defaultextension=DEFAULT_PUBKEY_EXTENSION,
            filetypes=PUBKEY_FILE_TYPES,
            initialfile=initial_filename,
            title="Save Signature As"
        )
        if save_path_str:
            save_path = Path(save_path_str)
            pubkey_str = str(self.key_manager.key.pubkey)
            try:
                save_path.write_text(pubkey_str, encoding='utf-8') # Explicit encoding
                logging.info(f"Signature saved to {save_path}")
            except OSError as e:
                logging.error(f"Error saving signature to {save_path}: {e}")
                # Optionally show an error message to the user via the UI
                self._update_attributes_display(f"Error saving signature:\n{e}")

    def _load_new_key(self):
        self.controller.key = self.key_manager.key
        self.controller.show_frame("SignFile")

    
    def _update_attributes_display(self, content, state=tk.DISABLED):
        """Helper method to update the text widget."""
        if self.attributes_display:
            self.attributes_display.config(state=tk.NORMAL)
            self.attributes_display.delete(1.0, tk.END)
            self.attributes_display.insert(tk.END, content)
            self.attributes_display.config(state=state)