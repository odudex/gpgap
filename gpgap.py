import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont
from pages import LoginPage, SignFile, NewKey
import ctypes

# Fix window scaling on Windows 10/11
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass  # If not on Windows or API not available

class GPGap(tk.Tk):
    """Main application class for GPGap GUI."""
    def __init__(self):
        super().__init__()
        self.title("GPGap - Air-gapped GPG")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        self.minsize(screen_width // 3, screen_height // 3)
        initial_width = int(screen_width * 0.5)
        initial_height = int(screen_height * 0.8)
        self.geometry(f"{initial_width}x{initial_height}")
        self.font_height = 22
        self._calculate_font_size(initial_height)

        # Create dynamic fonts based on initial height
        self.dynamic_font = tkfont.Font(family="TkDefaultFont")
        self.dynamic_font_small = tkfont.Font(family="TkDefaultFont")
        self.dynamic_font.configure(size=self.font_size)
        self.dynamic_font_small.configure(size=(3 * self.font_size) // 4)


        # Store colors
        self.bg_color = "black"
        self.fg_color = "white"
        self.entry_bg = "#2a2a2a"
        self.button_bg = "#4d4d4d"
        self.button_active = "#5d5d5d"

        # Configure ttk style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self._configure_styles() # Apply styles using the dynamic font

        # global variables
        self.key = None

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_rowconfigure(1, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # instantiate all pages and store in a dict
        self.frames = {}
        for Page in (LoginPage, SignFile, NewKey):
            page_name = Page.__name__
            frame = Page(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # show the first page
        self.show_frame("LoginPage")

        # Bind resize event to update font size
        self.bind("<Configure>", self._on_resize)

    def _calculate_font_size(self, height):
        """Calculate font size based on window height and width."""
        self.font_size = max(10, height // 100)

    def _configure_styles(self):
        """Configures the ttk styles using the dynamic font."""
        self.style.configure('.', background=self.bg_color, foreground=self.fg_color, font=self.dynamic_font)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=self.dynamic_font)
        self.style.configure(
            'TButton',
            background=self.button_bg,
            foreground=self.fg_color,
            borderwidth=0,
            relief='flat',
            focusthickness=0,
            focuscolor=self.bg_color,
            font=self.dynamic_font
        )
        self.style.map(
            'TButton',
            background=[('active', self.button_active)],
            relief=[('pressed', 'sunken')]
        )
        self.style.configure('TEntry',
                           fieldbackground=self.entry_bg,
                           foreground=self.fg_color,
                           insertcolor=self.fg_color,
                           font=self.dynamic_font)

    def _on_resize(self, event):
        """Handle window resize event to update font size."""
        # Only react to configure events on the main window itself
        if event.widget == self:
            self._calculate_font_size(self.winfo_height())

            # Update font size only if it has changed
            if self.font_size != self.dynamic_font.actual("size"):
                self.dynamic_font.configure(size=self.font_size)
                small_font_size = (3 * self.font_size) // 4
                small_font_size = max(10, small_font_size)
                self.dynamic_font_small.configure(size=small_font_size)


    def show_frame(self, page_name: str):
        """Raise the frame identified by page_name."""
        frame = self.frames[page_name]
        frame.tkraise()
        if hasattr(frame, "on_show"):
           frame.on_show()


    def on_closing(self):
        # self.media_display.stop_scan()
        self.destroy()

if __name__ == "__main__":
    app = GPGap()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()