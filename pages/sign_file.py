import tkinter as tk
from tkinter import ttk, filedialog
import hashlib
import binascii
from datetime import datetime, timezone
from pathlib import Path
import logging
from media import MediaDisplay

DEFAULT_SIG_EXTENSION = ".sig"
SIG_FILE_TYPES = [("Signature files", f"*{DEFAULT_SIG_EXTENSION}")]
DEFAULT_MANIFEST_EXTENSION = ".manifest.txt"
MANIFEST_FILE_TYPES = [("Manifest files", f"*{DEFAULT_MANIFEST_EXTENSION}")]
SIGNATURE_COMMENT = "Comment: GPGap experimental"
NOTATION_NAME = "signature"
NOTATION_VALUE = "GPGap"
TEXT_WIDGET_HEIGHT = 10

class SignFile(tk.Frame):
    """Class to handle file signing"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg=controller.bg_color)  # Comment this to debug widget areas

        self.key = None
        self.file_path: Path | None = None # Use type hints and Path
        self.file_data: bytes | None = None
        self.creation_time: datetime | None = None
        self.notation = {
            NOTATION_NAME: NOTATION_VALUE,
        }
        self.sig_data: bytes | None = None # Sig data as bytes
        self.final_sig: str | None = None # Final signature string

        self.fingerprint_label = ttk.Label(self, text="Fingerprint: ", anchor="center")
        
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
        self.create_load_frame()
        self.create_scan_frame()
        self.create_save_frame()

        # Media/QR/camera display
        self.media_display = MediaDisplay(self, padding="10")

    def on_show(self):
        """Called by the controller when the frame is shown."""
        self.grid_rowconfigure(1, weight=2)  # Attributes and info
        self.grid_rowconfigure(2, weight=1, minsize=self.controller.font_height * 4)  # Buttons
        self.grid_rowconfigure(3, weight=4)  # Media/QR/camera
        self.grid_columnconfigure(0, weight=1)

        self.key = self.controller.key
        for widget in self.grid_slaves():
            widget.grid_forget()
        self.fingerprint_label.config(
            text=f"Fingerprint: {self.key.fingerprint.__pretty__() if self.key else 'N/A'}",
            font=self.controller.dynamic_font_small,
        )
        self.fingerprint_label.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        self.attributes_display.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.attributes_display.config(font=self.controller.dynamic_font_small)
        self.media_display.grid(row=3, column=0, sticky="nsew")
        self.display_key_info()
        self.load_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        self.media_display.load_default_image()

    def create_load_frame(self):
        self.load_frame = ttk.Frame(self)
        self.load_frame.grid_rowconfigure(0, weight=1)
        self.load_frame.grid_columnconfigure(0, weight=1)
        self.load_frame.grid_columnconfigure(1, weight=1)
        self.back_from_load_button = ttk.Button(
            self.load_frame,
            text="Back",
            command=lambda: self.controller.show_frame("LoginPage"),
        )
        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)
        self.load_file_button = ttk.Button(
            self.load_frame, text="Load a File to Sign", command=self.load_file
        )
        self.load_file_button.grid(row=0, column=1, sticky="nsew", padx=10)

    def create_scan_frame(self):
        self.scan_frame = ttk.Frame(self)
        self.scan_frame.grid_rowconfigure(0, weight=1)
        self.scan_frame.grid_columnconfigure(0, weight=1)
        self.scan_frame.grid_columnconfigure(1, weight=1)
        self.back_from_scan_button = ttk.Button(
            self.scan_frame,
            text="Back",
            command=self.back_from_scan,
        )
        self.back_from_scan_button.grid(row=0, column=0, sticky="nsew", padx=10)
        self.scan_qr_button = ttk.Button(
            self.scan_frame, text="Scan", command=self.scan_qr
        )
        self.scan_qr_button.grid(row=0, column=1, sticky="nsew", padx=10)

    def create_save_frame(self):
        self.save_frame = ttk.Frame(self)
        self.save_frame.grid_rowconfigure(0, weight=1)
        self.save_frame.grid_columnconfigure(0, weight=1)
        self.save_frame.grid_columnconfigure(1, weight=1)
        self.save_sig_button = ttk.Button(
            self.save_frame, text="Save Signature", command=self.save_sig
        )
        self.save_sig_button.grid(row=0, column=0, sticky="nsew", padx=10)
        self.done_button = ttk.Button(
            self.save_frame,
            text="Done",
            command=lambda: self.controller.show_frame("LoginPage"),
        )
        self.done_button.grid(row=0, column=1, sticky="nsew", padx=10)
    
    def back_from_scan(self):
        """Handles the back button from the scan frame."""
        # Reset the UI to the load file state
        self.scan_frame.grid_forget()
        self.save_frame.grid_forget()
        self.load_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        self.display_key_info()
        self.media_display.load_default_image()

    def display_key_info(self):
        """Displays key information and resets the UI to the initial state."""

        # Reset state variables related to a specific file signing process
        self.file_path = None
        self.file_data = None
        self.creation_time = None
        self.sig_data = None
        self.final_sig = None

        # Prepare display strings
        user_name = "N/A"
        user_email = "N/A"
        info_text = ""

        # Check if a key is available (updated in on_show)
        if self.key:
            # Safely get the first userid details
            first_uid = next(iter(self.key.userids), None)
            if first_uid:
                user_name = first_uid.name
                user_email = first_uid.email
            # Set informative text for the display area
            # valid_uid = bool(self.key.pubkey.verify(first_uid, first_uid.selfsig))
            info_text = (
                f"Name: {user_name}\n"
                f"Email: {user_email}\n"
                # f"Valid UID: {'Yes' if valid_uid else 'No'}\n\n"
                f"You can now load a file to sign."
            )
            # Enable the file loading button as a key is present
            self._set_button_state(self.load_file_button, tk.NORMAL)
        else:
            # Inform the user that no key is loaded
            info_text = "No GPG key loaded.\nPlease load a key on the main page."
            # Disable the file loading button as no key is present
            self._set_button_state(self.load_file_button, tk.DISABLED)

        # Update the text display area
        self._update_attributes_display(info_text)

    def _update_attributes_display(self, content, state=tk.DISABLED):
        """Helper method to update the text widget."""
        if self.attributes_display:
            self.attributes_display.config(state=tk.NORMAL)
            self.attributes_display.delete(1.0, tk.END)
            self.attributes_display.insert(tk.END, content)
            self.attributes_display.config(state=state)

    def _set_button_state(self, button, state=tk.NORMAL):
        """Helper method to set button state."""
        if button and button.winfo_exists():
            button.config(state=state)

    def load_file(self):
        """Opens file dialog, loads file, calculates hash, generates sig_data."""
        file_path_str = filedialog.askopenfilename(title="Select File to Sign")
        if not file_path_str:
            return

        self.file_path = Path(file_path_str) # Use Path object

        try:
            self.file_data = self.file_path.read_bytes()
        except OSError as e:
            logging.error(f"Error reading file {self.file_path}: {e}")
            self._update_attributes_display(f"Error reading file:\n{e}")
            return

        # Hash the file data
        file_hash = hashlib.sha256(self.file_data).digest()

        # Display file path and hash
        self._update_attributes_display(
            f"File Path: {self.file_path}\n"
            f"File Hash: {file_hash.hex()}\n\n"
            "On Krux, scan the QR code then sign the file.\n"
            "1. Load your key\n"
            "2. Go to Wallet -> BIP85 -> GPG Key -> Index -> Sign File with GPG\n"
            "3. Scan the QR code below\n"
            "4. Scan back Krux's signature QR code"
        )

        # Generate sigdata
        self.creation_time = datetime.now(timezone.utc)
        try:
            # Assuming self.key.sign can raise exceptions
            self.sig_data = self.key.sign(
                self.file_data,
                extract=True,
                created=self.creation_time,
                notation=self.notation,
            )
        except Exception as e:
             logging.error(f"Error generating signature data: {e}")
             self._update_attributes_display(f"Error generating signature data:\n{e}")
             return

        sigdata_hash = hashlib.sha256(self.sig_data).hexdigest()
        self.media_display.export_qr_code_image(sigdata_hash)

        self.load_frame.grid_forget()
        self.scan_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        

    def scan_qr(self):
        """Starts the QR code scanning process."""
        self.scan_frame.grid_forget()
        self.media_display.start_scan() # Assuming this handles its own errors
        self.monitor_scan()

    def monitor_scan(self):
        """Checks for scanned QR code periodically."""
        if self.media_display.qr_found:
            self.media_display.stop_scan()
            self._process_scanned_signature()
        elif self.media_display.camera_running:
            # Schedule the next check
            self.after(100, self.monitor_scan)
        else:
            # Scan aborted, show scan button again
            self.scan_frame.grid(row=2, column=0, sticky="nsew", pady=10)
            # Show QR code again
            try:
                self.media_display.export_qr_code_image(
                    hashlib.sha256(self.sig_data).hexdigest()
                )
            except:
                pass


    def _process_scanned_signature(self):
        """Processes the QR code data once found."""
        base64_sig = self.media_display.qr_found
        self.media_display.qr_found = None

        try:
            # Convert signature from base64 string to bytes
            sig_bytes = binascii.a2b_base64(base64_sig)

            # Inject the scanned signature bytes
            sig = self.key.sign(
                self.file_data,
                inject=sig_bytes,
                ext_sig_data=self.sig_data,
                created=self.creation_time,
                notation=self.notation,
            )
            # Verify the generated signature immediately
            valid_sig = bool(self.key.pubkey.verify(self.file_data, sig))

            # Store the final signature as a string
            self.final_sig = str(sig)

            # A brand comment to the signature
            self.final_sig = self.final_sig.replace(
                "-----BEGIN PGP SIGNATURE-----",
                f"-----BEGIN PGP SIGNATURE-----\n{SIGNATURE_COMMENT}",
            )

            # Update display with signature and validity
            self._update_attributes_display(f"{self.final_sig}\n", state=tk.NORMAL) # Keep NORMAL to add tags
            if self.attributes_display:
                 self.attributes_display.tag_configure("valid", foreground="lime")
                 self.attributes_display.tag_configure("invalid", foreground="red")
                 if valid_sig:
                     self.attributes_display.insert("end", "Signature is valid", "valid")
                 else:
                     self.attributes_display.insert("end", "Bad Signature", "invalid")
                 self.attributes_display.config(state=tk.DISABLED) # Disable after adding tags

            self.save_frame.grid(row=2, column=0, sticky="nsew", pady=10)


        except binascii.Error as e:
            logging.error(f"Invalid Base64 data from QR code: {e}")
            self._update_attributes_display(f"Error decoding QR code:\nInvalid Base64 data.")
            # Show scan button again to allow retry
            if self.scan_qr_button:
                 self.scan_qr_button.pack(pady=5)
        except Exception as e: # Catch potential errors during sign/verify
            logging.error(f"Error processing signature: {e}")
            self._update_attributes_display(f"Error processing signature:\n{e}")
            # Show scan button again to allow retry
            if self.scan_qr_button:
                 self.scan_qr_button.pack(pady=5)


    def show_save_options(self):
        """Displays buttons to save the signature"""
        self.scan_frame.grid_forget()
    def save_sig(self):
        """Saves the generated signature to a file."""
        if self.final_sig and self.file_path:
            initial_filename = self.file_path.name + DEFAULT_SIG_EXTENSION
            save_path_str = filedialog.asksaveasfilename(
                defaultextension=DEFAULT_SIG_EXTENSION,
                filetypes=SIG_FILE_TYPES,
                initialfile=initial_filename,
                title="Save Signature As"
            )
            if save_path_str:
                save_path = Path(save_path_str)
                try:
                    save_path.write_text(self.final_sig, encoding='utf-8') # Explicit encoding
                    logging.info(f"Signature saved to {save_path}")
                except OSError as e:
                    logging.error(f"Error saving signature to {save_path}: {e}")
                    # Optionally show an error message to the user via the UI
                    self._update_attributes_display(f"Error saving signature:\n{e}")


    def save_manifest(self):
        """Saves a manifest file containing the original file's hash and name."""
        if self.file_path and self.file_data:
            initial_filename = self.file_path.name + DEFAULT_MANIFEST_EXTENSION
            save_path_str = filedialog.asksaveasfilename(
                defaultextension=DEFAULT_MANIFEST_EXTENSION,
                filetypes=MANIFEST_FILE_TYPES,
                initialfile=initial_filename,
                title="Save Manifest As"
            )
            if save_path_str:
                save_path = Path(save_path_str)
                file_name = self.file_path.name # Use Path.name
                try:
                    manifest_hash = hashlib.sha256(self.file_data).hexdigest()
                    manifest_content = f"{manifest_hash} *{file_name}\n"
                    save_path.write_text(manifest_content, encoding='utf-8') # Explicit encoding
                    logging.info(f"Manifest saved to {save_path}")
                except OSError as e:
                    logging.error(f"Error saving manifest to {save_path}: {e}")
                    # Optionally show an error message to the user via the UI
                    self._update_attributes_display(f"Error saving manifest:\n{e}")
