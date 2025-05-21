import tkinter as tk
from tkinter import ttk, filedialog
import hashlib
import binascii
from datetime import datetime, timezone
from pathlib import Path
import logging
from media import MediaDisplay
from tkinter import messagebox

DEFAULT_SIG_EXTENSION = ".sig"
SIG_FILE_TYPES = [("Signature files", f"*{DEFAULT_SIG_EXTENSION}")]
DEFAULT_MANIFEST_EXTENSION = ".manifest.txt"
MANIFEST_FILE_TYPES = [("Manifest files", f"*{DEFAULT_MANIFEST_EXTENSION}")]
SIGNATURE_COMMENT = "Comment: Krux/GPGap (experimental)"
NOTATION_NAME = "signature"
NOTATION_VALUE = "GPGap"

TEXT_WIDGET_HEIGHT = 10
BUTTONS_ROW = 2
BUTTONS_COLUMN = 0


class SignFile(tk.Frame):
    """Class to handle file signing"""

    # UI states
    UI_STATE_LOAD_FILE = 0
    UI_STATE_SCAN = 1
    UI_STATE_SAVE = 2

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg=controller.bg_color)  # Comment this to debug widget areas

        self.key = None
        self.file_path: Path | None = None  # Use type hints and Path
        self.file_data: bytes | None = None
        self.creation_time: datetime | None = None
        self.notation = {
            NOTATION_NAME: NOTATION_VALUE,
        }
        self.sig_data: bytes | None = None  # Sig data as bytes
        self.final_sig: str | None = None  # Final signature string

        # Always shown widgets
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
        # Media/QR/camera display
        self.media_display = MediaDisplay(self, padding="10")

        # Intermittent widget fames
        self.create_load_frame()
        self.create_scan_frame()
        self.create_save_frame()

    def create_load_frame(self):
        self.load_frame = ttk.Frame(self)
        self.load_frame.grid_rowconfigure(0, weight=1)
        self.load_frame.grid_columnconfigure(0, weight=1)
        self.load_frame.grid_columnconfigure(2, weight=1)
        self.back_from_load_button = ttk.Button(
            self.load_frame,
            text="Back",
            command=lambda: self.controller.show_frame("LoginPage"),
        )

        separator = ttk.Separator(self.load_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)
        self.load_file_button = ttk.Button(
            self.load_frame, text="Load a File to Sign", command=self.load_file
        )
        self.load_file_button.grid(row=0, column=2, sticky="nsew", padx=10)

        separator = ttk.Separator(self.load_frame, orient="horizontal")
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

    def create_scan_frame(self):
        self.scan_frame = ttk.Frame(self)
        self.scan_frame.grid_rowconfigure(0, weight=1)
        self.scan_frame.grid_columnconfigure(0, weight=1)
        self.scan_frame.grid_columnconfigure(2, weight=1)
        self.back_from_scan_button = ttk.Button(
            self.scan_frame,
            text="Back",
            command=self.back_from_scan,
        )
        self.back_from_scan_button.grid(row=0, column=0, sticky="nsew", padx=10)

        separator = ttk.Separator(self.scan_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.scan_qr_button = ttk.Button(
            self.scan_frame, text="Scan", command=self.scan_qr
        )
        self.scan_qr_button.grid(row=0, column=2, sticky="nsew", padx=10)

        separator = ttk.Separator(self.scan_frame, orient="horizontal")
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

    def create_save_frame(self):
        self.save_frame = ttk.Frame(self)
        self.save_frame.grid_rowconfigure(0, weight=1)
        self.save_frame.grid_columnconfigure(0, weight=1)
        self.save_frame.grid_columnconfigure(2, weight=1)
        self.save_frame.grid_columnconfigure(4, weight=1)
        self.save_sig_button = ttk.Button(
            self.save_frame, text="Save Signature", command=self.save_sig
        )
        self.save_sig_button.grid(row=0, column=0, sticky="nsew", padx=10)

        separator = ttk.Separator(self.save_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.other_sig_button = ttk.Button(
            self.save_frame, text="Sign Other File", command=self.sign_other_file
        )
        self.other_sig_button.grid(row=0, column=2, sticky="nsew", padx=10)

        separator = ttk.Separator(self.save_frame, orient="vertical")
        separator.grid(row=0, column=3, sticky="ns", padx=5, pady=5)

        self.done_button = ttk.Button(
            self.save_frame,
            text="Done",
            command=lambda: self.controller.show_frame("LoginPage"),
        )
        self.done_button.grid(row=0, column=4, sticky="nsew", padx=10)

        separator = ttk.Separator(self.save_frame, orient="horizontal")
        separator.grid(row=1, column=0, columnspan=5, sticky="ew", padx=5, pady=5)

    def on_show(self):
        """Called by the controller when the frame is shown."""
        # self.grid_rowconfigure(1, weight=1)  # Attributes and info
        self.grid_rowconfigure(
            2, weight=1, minsize=self.controller.font_size * 4
        )  # Buttons
        self.grid_rowconfigure(3, weight=4)  # Media/QR/camera
        self.grid_columnconfigure(0, weight=1)

        self.key = self.controller.key
        self.fingerprint_label.config(
            text=f"Fingerprint: {self.key.fingerprint.__pretty__() if self.key else 'N/A'}",
            font=self.controller.dynamic_font_small,
        )
        self.fingerprint_label.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        self.attributes_display.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        self.attributes_display.config(font=self.controller.dynamic_font_small)
        self.media_display.grid(row=3, column=0, sticky="nsew")
        self.media_display.grid_propagate(False)
        self._set_ui_state(self.UI_STATE_LOAD_FILE)

    def _set_ui_state(self, new_state):
        """Centralized method to manage UI frame visibility and related setup."""
        # Remove buttons from previous state
        for widget in self.grid_slaves(row=BUTTONS_ROW, column=BUTTONS_COLUMN):
            widget.grid_forget()

        # Reset button row to default (can be overridden by specific states)
        self.grid_rowconfigure(2, weight=1, minsize=self.controller.font_size * 4)

        if new_state == self.UI_STATE_LOAD_FILE:
            self.load_frame.grid(
                row=BUTTONS_ROW, column=BUTTONS_COLUMN, sticky="nsew", pady=10
            )
            self.display_key_info()  # Resets file-specific data and updates display
            self.media_display.load_default_image()
        elif new_state == self.UI_STATE_SCAN:
            self.scan_frame.grid(
                row=BUTTONS_ROW, column=BUTTONS_COLUMN, sticky="nsew", pady=10
            )
            self._generate_sig_data()  # Generate signature data
        elif new_state == self.UI_STATE_SAVE:
            self.save_frame.grid(
                row=BUTTONS_ROW, column=BUTTONS_COLUMN, sticky="nsew", pady=10
            )
            self.media_display.load_default_image()

    def back_from_scan(self):
        """Handles the back button from the scan frame."""
        self._set_ui_state(self.UI_STATE_LOAD_FILE)

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

        first_uid = next(iter(self.key.userids), None)
        if first_uid:
            user_name = first_uid.name
            user_email = first_uid.email
        info_text = (
            f"Name: {user_name}\n"
            f"Email: {user_email}\n"
        )

        # Update the text display area
        self._update_attributes_display(info_text)

    def _update_attributes_display(self, content, state=tk.DISABLED):
        """Helper method to update the text widget."""
        if self.attributes_display:
            self.attributes_display.config(state=tk.NORMAL)
            self.attributes_display.delete(1.0, tk.END)
            self.attributes_display.insert(tk.END, content)
            self.attributes_display.config(state=state)

    def load_file(self):
        """Opens file dialog, loads file, calculates hash, generates sig_data."""
        file_path_str = filedialog.askopenfilename(title="Select File to Sign")
        if not file_path_str:
            return

        self.file_path = Path(file_path_str)  # Use Path object

        try:
            self.file_data = self.file_path.read_bytes()
        except OSError as e:
            logging.error(f"Error reading file {self.file_path}: {e}")
            messagebox.showerror("File Error", f"Error reading file:\n{e}")
            return
        self._set_ui_state(self.UI_STATE_SCAN)  # Switch to scan state

    def _generate_sig_data(self):
        """Generates the signature data from the file data."""
        if not self.file_data:
            raise ValueError("File data is empty or None.")
        # Hash the file data
        file_hash = hashlib.sha256(self.file_data).digest()

        # Display file path and hash
        self._update_attributes_display(
            f"File Hash: {file_hash.hex()}\n"
            "  1. On your Krux:\n"
            "    Load your mnemonic (from which you derived your GPG key).\n"
            "  2. On Krux home menu, go to:\n"
            "    Wallet -> BIP85 -> GPG Key -> Type an index -> Sign File with GPG\n"
            "  3. Still on your Krux:\n"
            "    Scan the QR code from GPGap screen.\n"
            "  4. On GPGap:\n"
            "    Scan the signature QR code exported by Krux.\n"
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

    def scan_qr(self):
        """Starts the QR code scanning process."""
        self.scan_frame.grid_forget()
        self.grid_rowconfigure(2, weight=0, minsize=0)  # Shrink Buttons
        self.media_display.start_scan()  # Assuming this handles its own errors
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
            self._set_ui_state(self.UI_STATE_SCAN)

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
                created=self.creation_time,
                notation=self.notation,
            )
            # Verify the generated signature immediately
            valid_sig = bool(self.key.pubkey.verify(self.file_data, sig))

            if not valid_sig:
                raise ValueError("Invalid signature data.")

            # Store the final signature as a string
            self.final_sig = str(sig)

            # A brand comment to the signature
            self.final_sig = self.final_sig.replace(
                "-----BEGIN PGP SIGNATURE-----",
                f"-----BEGIN PGP SIGNATURE-----\n{SIGNATURE_COMMENT}",
            )

            # Update display with signature and validity
            self._update_attributes_display(f"{self.final_sig}\n", state=tk.NORMAL)

            self.grid_rowconfigure(
                2, weight=1, minsize=self.controller.font_size * 4
            )  # Buttons
            self._set_ui_state(self.UI_STATE_SAVE)  # Switch to save state
            return

        except binascii.Error as e:
            logging.error(f"Invalid Base64 data from QR code: {e}")
            messagebox.showerror(
                "QR Code Error", "Error decoding QR code:\nInvalid Base64 data."
            )
        except Exception as e:  # Catch potential errors during sign/verify
            logging.error(f"Error processing signature: {e}")
            messagebox.showerror(
                "Signature Processing Error", f"Error processing signature:\n{e}"
            )

        # Restart the scan if an error occurs
        self._set_ui_state(self.UI_STATE_SCAN)

    def save_sig(self):
        """Saves the generated signature to a file."""
        if self.final_sig and self.file_path:
            initial_filename = self.file_path.name + DEFAULT_SIG_EXTENSION
            save_path_str = filedialog.asksaveasfilename(
                defaultextension=DEFAULT_SIG_EXTENSION,
                filetypes=SIG_FILE_TYPES,
                initialfile=initial_filename,
                title="Save Signature As",
            )
            if save_path_str:
                save_path = Path(save_path_str)
                try:
                    save_path.write_text(
                        self.final_sig, encoding="utf-8"
                    )  # Explicit encoding
                    messagebox.showinfo(
                        "Signature Saved",
                        f"Signature saved to {save_path}",
                    )
                    logging.info(f"Signature saved to {save_path}")
                except OSError as e:
                    logging.error(f"Error saving signature to {save_path}: {e}")
                    # Optionally show an error message to the user via the UI
                    self._update_attributes_display(f"Error saving signature:\n{e}")

    def sign_other_file(self):
        """Handles the action of signing another file."""
        self._set_ui_state(self.UI_STATE_LOAD_FILE)
