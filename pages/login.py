import tkinter as tk
from tkinter import ttk, filedialog
from PGPy import pgpy
from media import MediaDisplay
from key import KeyManager


class LoginPage(tk.Frame):
    """
    Login page that allows users to load existing GPG keys or create new key pairs.
    """

    def __init__(self, parent, controller):
        """
        Initialize the LoginPage frame with key management options.
        """
        super().__init__(parent)
        self.controller = controller
        self.configure(bg=controller.bg_color)

        screen_height = self.winfo_screenheight()
        min_height = screen_height // 4
        self.grid_rowconfigure(0, weight=1, minsize=min_height)
        self.grid_rowconfigure(1, weight=2)
        self.grid_columnconfigure(0, weight=1)

        self.menu_frame = ttk.Frame(self, padding="10")
        self.menu_frame.grid(row=0, column=0, sticky="nsew")
        self.menu_frame.grid_rowconfigure(0, weight=1)
        self.menu_frame.grid_rowconfigure(2, weight=1)
        self.menu_frame.grid_columnconfigure(0, weight=1)

        # Media/QR/camera display
        self.media_display = MediaDisplay(self, padding="10")
        self.media_display.grid(row=1, column=0, sticky="nsew")

        # Pubkey frame widgets
        self.setup_menu_frame()

    def on_show(self):
        """
        Called when this page is shown to the user.
        """
        self.media_display.grid_propagate(False)
        self.media_display.load_default_image()

    def setup_menu_frame(self):
        """
        Configure and place the buttons for key management in the menu frame.
        """
        # Pubkey load button
        self.open_button = ttk.Button(
            self.menu_frame, text="Load GPG Public Key", command=self.open_gpg_file
        )
        self.open_button.grid(row=0, column=0, sticky="nsew", padx=10, pady=5)

        separator = ttk.Separator(self.menu_frame, orient="horizontal")
        separator.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        # Pubkey create button
        self.create_button = ttk.Button(
            self.menu_frame,
            text="Create GPG Key Pair",
            command=self.create_gpg_key_pair,
        )
        self.create_button.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        separator = ttk.Separator(self.menu_frame, orient="horizontal")
        separator.grid(row=3, column=0, sticky="ew", padx=10, pady=5)

    def open_gpg_file(self):
        """
        Open a file dialog to select and load a GPG public key file.
        If successful, loads the key into the application and navigates to the SignFile page.
        """
        file_path = filedialog.askopenfilename(
            title="Open GPG Public Key",
            filetypes=[("GPG Files", "*.asc *.pgp"), ("All Files", "*.*")],
        )

        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                key_data = f.read()

            pubkey, _ = pgpy.PGPKey.from_blob(key_data)
            self.controller.key = KeyManager().load_key(pubkey)
            self.controller.show_frame("SignFile")

        except Exception as e:
            print(f"Error: {str(e)}")
            # Show error to user through messagebox
            from tkinter import messagebox

            messagebox.showerror(
                "Error Loading Key", f"Failed to load GPG key: {str(e)}"
            )

    def create_gpg_key_pair(self):
        """
        Navigate to the NewKey page to create a new GPG key pair.
        """
        self.controller.show_frame("NewKey")
