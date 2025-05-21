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

TEXT_WIDGET_HEIGHT = 5
ENTRIES_ROW = 1
ENTRIES_COLUMN = 0
BUTTONS_ROW = 2
BUTTONS_COLUMN = 0


DEFAULT_PUBKEY_EXTENSION = ".asc"
PUBKEY_FILE_TYPES = [("Public key files", f"*{DEFAULT_PUBKEY_EXTENSION}")]

METADATA_INFO = "Step 1/4\nFill your GPG public information.\n"

SCAN_PUB_KEY_INFO = (
    "Step 2/4\n"
    "  1. On your Krux:\n"
    "    Create, backup and load a mnemonic as usual.\n"
    "    (Bitcoin wallet settings won't affect GPG key)\n"
    "  2. On Krux home menu, go to:\n"
    "    Wallet -> BIP85 -> GPG Key -> Type an index -> Create GPG Public Key.\n"
    "  3. On GPGap:\n"
    "    Scan the QR Code exported by Krux containing the hex public key.\n"
)
CERTIFY_INFO = (
    "Step 3/4\n"
    "  1. On your Krux:"
    '   Chose "Yes" to "Scan and sign GPG public key metadata".\n'
    "  2. Still on your Krux:\n"
    "    Scan the QR code from GPGap screen.\n"
    "  3. On GPGap:\n"
    "    Scan the signature QR code exported by Krux.\n"
)


class NewKey(tk.Frame):
    """Page for new key creation."""

    # UI states
    COLLECTING_USER_INFO = 1
    SCANNING_PUBKEY = 2
    AWAITING_CERTIFICATION = 3
    COMPLETED = 4

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg=controller.bg_color)

        self.user_name = ""
        self.user_email = ""
        self.key_manager = None
        self.sig_data = None
        self.key = None

        # Initialize UI components
        self._init_ui_components()

    def __del__(self):
        """Clean up resources when object is destroyed."""
        self.cleanup_camera()

    def _init_ui_components(self):
        """Initialize all UI components."""
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

        self.media_display = MediaDisplay(self, padding="10")

        # Frames that will be shown/hidden based on state
        self.scan_buttons_frame = ttk.Frame(self)
        self.user_info_frame = ttk.Frame(self)
        self.pubkey_options_frame = ttk.Frame(self)

    def _init_state(self):
        """Initialize state variables."""

        # User data state
        self.user_name = ""
        self.user_email = ""

        # Key state
        self.key_manager = KeyManager()  # Creates a new KeyManager for the session
        self.sig_data = None
        self.key = None

    def cleanup_camera(self):
        """Ensure camera resources are released."""
        if hasattr(self, "media_display") and self.media_display.camera_running:
            self.media_display.stop_scan()

    def on_show(self):
        """Called when the frame is shown."""
        # Clear previous UI
        self._clear_ui()

        # Set up grid configuration
        self._setup_grid()

        # Reset state and transition to initial state
        self._init_state()
        self._set_ui_state(self.COLLECTING_USER_INFO)

    def _clear_ui(self):
        """Clear all widgets from grid."""
        for widget in self.grid_slaves():
            widget.grid_forget()

    def _setup_grid(self):
        """Set up the grid layout."""
        self.grid_rowconfigure(0, weight=1)  # Attributes and info
        self.grid_rowconfigure(
            ENTRIES_ROW, minsize=self.controller.font_size * 6
        )  # Entries
        self.grid_rowconfigure(
            BUTTONS_ROW, weight=1, minsize=self.controller.font_size * 4
        )
        self.grid_rowconfigure(3, weight=3)  # Media/QR/camera
        self.grid_columnconfigure(0, weight=1)

        # Common elements always visible
        self.attributes_display.config(font=self.controller.dynamic_font_small)
        self.attributes_display.grid(
            row=0, column=0, sticky="nsew", padx=10, pady=(10, 5)
        )
        self.media_display.grid(row=3, column=0, sticky="nsew")
        self.media_display.grid_propagate(False)

    def _set_ui_state(self, new_state):
        """
        Transition to a new state.
        """

        # Stop camera if running
        self.cleanup_camera()

        # Remove entries from previous state
        for widget in self.grid_slaves(row=ENTRIES_ROW, column=ENTRIES_COLUMN):
            widget.grid_forget()

        # Remove buttons from previous state
        for widget in self.grid_slaves(row=BUTTONS_ROW, column=BUTTONS_COLUMN):
            widget.grid_forget()

        if new_state == self.COLLECTING_USER_INFO:
            self._handle_collecting_info()
        elif new_state == self.SCANNING_PUBKEY:
            self._handle_scanning_pubkey()
        elif new_state == self.AWAITING_CERTIFICATION:
            self._handle_awaiting_certification()
        elif new_state == self.COMPLETED:
            self._handle_completed()
        else:
            raise ValueError(f"Unknown state: {new_state}")

    # State handlers
    def _handle_collecting_info(self):
        """Handle collecting user information state."""
        self._update_attributes_display(METADATA_INFO)
        self.media_display.load_default_image()
        self._setup_user_info_frame()

    def _handle_scanning_pubkey(self):
        """Handle scanning public key state."""
        self._update_attributes_display(SCAN_PUB_KEY_INFO)
        self.media_display.load_default_image()
        self._setup_scan_buttons(
            back_command=lambda: self._set_ui_state(self.COLLECTING_USER_INFO),
            scan_command=lambda: self._start_scan(False),
        )

    def _handle_awaiting_certification(self):
        """Handle awaiting certification state."""
        self._update_attributes_display(CERTIFY_INFO)
        # Display QR code for certification
        if self.sig_data:
            self.media_display.export_qr_code_image(
                hashlib.sha256(self.sig_data).hexdigest()
            )
        self._setup_scan_buttons(
            back_command=lambda: self._set_ui_state(self.SCANNING_PUBKEY),
            scan_command=lambda: self._start_scan(True),
        )

    def _handle_completed(self):
        """Handle completed state."""
        self._update_attributes_display(
            "Step 4/4\n"
            "Key successfully certified.\n\n"
            f"Key fingerprint:\n{self.key_manager.key.fingerprint.__pretty__()}\n\n"
            "You can now save the key for later use, or load and use it to sign files right now."
        )
        self._setup_completed_options()

    # UI Setup methods
    def _setup_user_info_frame(self):
        """Set up user information entry frame."""
        # Clear existing widgets from self.user_info_frame before adding new ones
        for widget in self.user_info_frame.winfo_children():
            widget.destroy()

        # Configure and grid the existing frame
        self.user_info_frame.grid(
            row=ENTRIES_ROW, column=ENTRIES_COLUMN, sticky="ew", padx=10, pady=5
        )
        self.user_info_frame.rowconfigure(0, weight=1)
        self.user_info_frame.rowconfigure(1, weight=1)
        self.user_info_frame.columnconfigure(1, weight=1)

        # Add name field
        name_label = ttk.Label(self.user_info_frame, text="Name:")
        name_label.grid(row=0, column=0, sticky="w", padx=5, pady=0)
        self.name_entry = ttk.Entry(
            self.user_info_frame, font=self.controller.dynamic_font
        )
        self.name_entry.insert(0, self.user_name)
        self.name_entry.grid(row=0, column=1, sticky="ew", padx=(5, 10), pady=5)

        # Add email field
        email_label = ttk.Label(self.user_info_frame, text="Email:")
        email_label.grid(row=1, column=0, sticky="w", padx=5, pady=0)
        self.email_entry = ttk.Entry(
            self.user_info_frame, font=self.controller.dynamic_font
        )
        self.email_entry.insert(0, self.user_email)
        self.email_entry.grid(row=1, column=1, sticky="ew", padx=(5, 10), pady=5)

        # Add buttons frame
        user_info_buttons_frame = ttk.Frame(self)
        user_info_buttons_frame.rowconfigure(0, weight=1)
        user_info_buttons_frame.columnconfigure(0, weight=1)
        user_info_buttons_frame.columnconfigure(2, weight=1)
        user_info_buttons_frame.grid(
            row=BUTTONS_ROW, column=BUTTONS_COLUMN, sticky="nsew", padx=5, pady=5
        )

        # Add back and next buttons
        back_btn = ttk.Button(
            user_info_buttons_frame,
            text="< Back",
            command=lambda: self.controller.show_frame("LoginPage"),
        )
        back_btn.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        separator = ttk.Separator(user_info_buttons_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        next_btn = ttk.Button(
            user_info_buttons_frame,
            text="Next",
            command=self._validate_and_store_user_info,
        )
        next_btn.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)

    def _validate_and_store_user_info(self):
        """Validate and store user information."""
        name = self.name_entry.get()
        email = self.email_entry.get()

        if not name or not email:
            messagebox.showerror("Input Error", "Both name and email are required.")
            return

        if not self._validate_email(email):
            messagebox.showerror("Input Error", "Please enter a valid email address.")
            return

        # Store validated info
        self.user_name = name
        self.user_email = email

        # Shrinks entries frame
        self.grid_rowconfigure(1, weight=0, minsize=0)
        # Transition to next state
        self._set_ui_state(self.SCANNING_PUBKEY)

    def _setup_scan_buttons(self, back_command, scan_command):
        """Set up scan buttons with specified commands."""
        self.grid_rowconfigure(
            BUTTONS_ROW, weight=1, minsize=self.controller.font_size * 4
        )
        self.scan_buttons_frame.columnconfigure(0, weight=1)
        self.scan_buttons_frame.columnconfigure(2, weight=1)
        self.scan_buttons_frame.rowconfigure(0, weight=1)
        self.scan_buttons_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

        # Add back and scan buttons
        self.back_btn = ttk.Button(
            self.scan_buttons_frame, text="< Back", command=back_command
        )
        self.back_btn.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

        separator = ttk.Separator(self.scan_buttons_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.scan_button = ttk.Button(
            self.scan_buttons_frame, text="Scan", command=scan_command
        )
        self.scan_button.grid(row=0, column=2, sticky="nsew", padx=10, pady=5)

    def _setup_completed_options(self):
        """Set up options for completed state."""
        self.grid_rowconfigure(
            BUTTONS_ROW, weight=1, minsize=self.controller.font_size * 4
        )

        # Clear existing widgets from self.pubkey_options_frame
        for widget in self.pubkey_options_frame.winfo_children():
            widget.destroy()

        # Configure and grid the existing frame
        self.pubkey_options_frame.grid(
            row=BUTTONS_ROW, column=BUTTONS_COLUMN, sticky="nsew", padx=5, pady=5
        )
        self.pubkey_options_frame.rowconfigure(0, weight=1)
        self.pubkey_options_frame.columnconfigure(0, weight=1)
        self.pubkey_options_frame.columnconfigure(2, weight=1)

        # Add save and load buttons
        save_btn = ttk.Button(
            self.pubkey_options_frame, text="Save Public Key", command=self.save_key
        )
        save_btn.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        separator = ttk.Separator(self.pubkey_options_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        load_btn = ttk.Button(
            self.pubkey_options_frame, text="Load Key", command=self._load_new_key
        )
        load_btn.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)

    def _start_scan(self, is_certification):
        """Start the QR code scanning process."""
        self.scan_buttons_frame.grid_forget()
        self.grid_rowconfigure(BUTTONS_ROW, weight=0, minsize=0)
        try:
            self.media_display.start_scan()
            self._monitor_scan(is_certification)
        except Exception as e:
            logging.error(f"Error starting scan: {e}")
            # Restore UI to the state before attempting scan
            if is_certification:
                # Came from AWAITING_CERTIFICATION state
                back_cmd = lambda: self._set_ui_state(self.SCANNING_PUBKEY)
                scan_cmd = lambda: self._start_scan(True)
            else:
                # Came from SCANNING_PUBKEY state
                back_cmd = lambda: self._set_ui_state(self.COLLECTING_USER_INFO)
                scan_cmd = lambda: self._start_scan(False)
            self._setup_scan_buttons(back_command=back_cmd, scan_command=scan_cmd)
            self.cleanup_camera()

    def _monitor_scan(self, is_certification):
        """Monitor the QR code scanning process."""
        if not self.media_display.camera_running:
            # Camera was stopped externally
            if is_certification:
                self._set_ui_state(self.AWAITING_CERTIFICATION)
            else:
                self._set_ui_state(self.SCANNING_PUBKEY)
            return

        if self.media_display.qr_found:
            self.cleanup_camera()
            try:
                if is_certification:
                    self._process_certification_data()
                else:
                    self._process_pubkey_data()
            except Exception as e:
                messagebox.showerror("Scan Error", str(e))
        else:
            # Schedule next check
            self.after(100, lambda: self._monitor_scan(is_certification))

    def _process_pubkey_data(self):
        """Process the scanned public key data."""
        hex_key_material = self.media_display.qr_found
        self.media_display.qr_found = None

        try:
            key_material = bytes.fromhex(hex_key_material)
            if len(key_material) != 64:
                raise ValueError("Invalid key material length.")

            self.sig_data = self.key_manager.create_key(
                self.user_name,
                self.user_email,
                key_material,
            )
            self._set_ui_state(self.AWAITING_CERTIFICATION)
        except Exception as e:
            messagebox.showerror("Scan Error", f"Error processing scanned pubkey:\n{e}")
            self._set_ui_state(self.SCANNING_PUBKEY)

    def _process_certification_data(self):
        """Process the scanned certification data."""
        scanned_data = self.media_display.qr_found
        self.media_display.qr_found = None

        try:
            cert_bytes = binascii.a2b_base64(scanned_data)
            self.key_manager.inject_key(injected_cert=cert_bytes)
            # Verify signature
            pubkey_str = str(self.key_manager.key.pubkey)
            pubkey, _ = pgpy.PGPKey.from_blob(pubkey_str)
            first_uid = next(iter(pubkey.userids), None)
            uid_valid_sig = bool(pubkey.verify(first_uid, first_uid.selfsig))

            if uid_valid_sig:
                self._set_ui_state(self.COMPLETED)
            else:
                raise ValueError("Signature verification failed.")
        except Exception as e:
            messagebox.showerror(
                "Scan Error", f"Error processing scanned certification:\n{e}"
            )
            self._set_ui_state(self.AWAITING_CERTIFICATION)

    # Existing methods with minor modifications
    def save_key(self):
        """Save the key to a file."""
        initial_filename = f"{self.user_name}{DEFAULT_PUBKEY_EXTENSION}"
        save_path_str = filedialog.asksaveasfilename(
            defaultextension=DEFAULT_PUBKEY_EXTENSION,
            filetypes=PUBKEY_FILE_TYPES,
            initialfile=initial_filename,
            title="Save Public Key As",
        )

        if save_path_str:
            save_path = Path(save_path_str)
            pubkey_str = str(self.key_manager.key.pubkey)
            try:
                save_path.write_text(pubkey_str, encoding="utf-8")
                logging.info(f"Public key saved to {save_path}")
                messagebox.showinfo(
                    "Save Successful", f"Public key saved to {save_path}"
                )
            except OSError as e:
                logging.error(f"Error saving public key to {save_path}: {e}")
                messagebox.showerror("Save Error", f"Error saving public key:\n{e}")

    def _load_new_key(self):
        """Load the created key and navigate to Sign page."""
        self.controller.key = self.key_manager.key
        self.controller.show_frame("SignPage")

    def _update_attributes_display(self, content, state=tk.DISABLED):
        """Helper method to update the text widget."""
        if self.attributes_display:
            self.attributes_display.config(state=tk.NORMAL)
            self.attributes_display.delete(1.0, tk.END)
            self.attributes_display.insert(tk.END, content)
            self.attributes_display.config(state=state)

    def _validate_email(self, email):
        """Validate email format using a simple regex pattern."""
        import re

        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, email) is not None
