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

from git.repo import Repo
from git.objects.commit import Commit

TEXT_WIDGET_HEIGHT = 5
BUTTONS_ROW = 2
MEDIA_ROW = 3

class SignCommits(tk.Frame):

    SELECT_PROJECT_FOLDER = 0
    SELECT_AUTHOR = 1
    SCAN_PROJECT_COMMITS = 2
    EXPORT_COMMIT_QR = 3
    SCAN_COMMIT_SIGNATURE = 4

    def __init__(self, parent, controller):
        ttk.Frame.__init__(self, parent)
        self.controller = controller
        self.project_folder = None
        self.author_commits = []
        self.author = None
        self.commit_hash = None
        
        self.create_widgets()

        self._create_select_folder_frame()
        self._create_select_author_btns_frame()
        self._create_commit_list_btns_frame()
        self._create_commit_export_qr_btns_frame()

    def create_widgets(self):
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

    def _create_select_folder_frame(self):
        self.sel_folder_frame = ttk.Frame(self)
        self.sel_folder_frame.grid_rowconfigure(0, weight=1)
        self.sel_folder_frame.grid_columnconfigure(0, weight=1)
        self.sel_folder_frame.grid_columnconfigure(2, weight=1)
        self.back_from_load_button = ttk.Button(
            self.sel_folder_frame,
            text="< Back",
            command=lambda: self.controller.show_frame("SignPage"),
        )
        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)

        separator = ttk.Separator(self.sel_folder_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.load_proj_folder_btn = ttk.Button(
            self.sel_folder_frame, text="Select a Project Folder", command=self._sel_project_folder
        )
        self.load_proj_folder_btn.grid(row=0, column=2, sticky="nsew", padx=10)

    
    def _create_select_author_btns_frame(self):
        """Create a frame to select an author from the list of commit authors."""
        self.sel_author_btns_frame = ttk.Frame(self)
        self.sel_author_btns_frame.grid_rowconfigure(0, weight=1)
        self.sel_author_btns_frame.grid_columnconfigure(0, weight=1)
        self.sel_author_btns_frame.grid_columnconfigure(2, weight=1)
        self.back_from_load_button = ttk.Button(
            self.sel_author_btns_frame,
            text="< Back",
            command=lambda: self._set_ui_state(self.SELECT_PROJECT_FOLDER),
        )
        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)


    def load_author_commits(self, event=None):
        # Ensure the event comes from the correct listbox
        if event and event.widget != self.author_lb:
            return
        selected_indices = self.author_lb.curselection()
        if not selected_indices:
            return
        selected_index = selected_indices[0]
        selected_author = self.author_lb.get(selected_index)
        self.author = selected_author.split(":")[0].strip()
        if self.author:
            self._set_ui_state(self.SCAN_PROJECT_COMMITS)

    def _create_commit_list_btns_frame(self):
        """Create a frame to display the list of commits for the selected author."""
        self.commit_list_btns_frame = ttk.Frame(self)
        self.commit_list_btns_frame.grid_rowconfigure(0, weight=1)
        self.commit_list_btns_frame.grid_columnconfigure(0, weight=1)
        self.commit_list_btns_frame.grid_columnconfigure(2, weight=1)
        self.back_from_load_button = ttk.Button(
            self.commit_list_btns_frame,
            text="< Back",
            command=lambda: self._set_ui_state(self.SELECT_AUTHOR),
        )
        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)

        separator = ttk.Separator(self.commit_list_btns_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.load_commits_btn = ttk.Button(
            self.commit_list_btns_frame,
            text="Sign Commit",
            command=self.load_commit_hash,
        )
        self.load_commits_btn.grid(row=0, column=2, sticky="nsew", padx=10)

    def load_commit_hash(self):
        try:
            selected_index = self.lb_commit.curselection()[0]
            self.commit_hash = self.author_commits[selected_index]['sha']
        except:
            messagebox.showerror(
                "No Commit Selected",
                "Please select a commit to sign.",
            )
            return
        if self.commit_hash:
            self._set_ui_state(self.EXPORT_COMMIT_QR)


    def _create_commit_export_qr_btns_frame(self):
        """Create a frame to export the commit QR code."""
        self.commit_export_qr_btns_frame = ttk.Frame(self)
        self.commit_export_qr_btns_frame.grid_rowconfigure(0, weight=1)
        self.commit_export_qr_btns_frame.grid_columnconfigure(0, weight=1)
        self.commit_export_qr_btns_frame.grid_columnconfigure(2, weight=1)
        self.back_from_load_button = ttk.Button(
            self.commit_export_qr_btns_frame,
            text="< Back",
            command=lambda: self._set_ui_state(self.SCAN_PROJECT_COMMITS),
        )
        self.back_from_load_button.grid(row=0, column=0, sticky="nsew", padx=10)

        separator = ttk.Separator(self.commit_export_qr_btns_frame, orient="vertical")
        separator.grid(row=0, column=1, sticky="ns", padx=5, pady=5)

        self.export_commit_qr_btn = ttk.Button(
            self.commit_export_qr_btns_frame,
            text="Scan Commit Signature",
            command=None  # lambda: self._set_ui_state(self.EXPORT_COMMIT_QR),
        )
        self.export_commit_qr_btn.grid(row=0, column=2, sticky="nsew", padx=10)

    def _create_select_author_frame(self):
        authors_eval = self._eval_commit_authors()
        # Create a list of authors
        authors = [f"{author}: {count}" for author, count in authors_eval]
        self.sel_author_frame = ttk.Frame(self)
        self.sel_author_frame.grid_rowconfigure(0, weight=1)
        self.sel_author_frame.grid_columnconfigure(0, weight=1)
        scrollbar = tk.Scrollbar(self.sel_author_frame, orient=tk.VERTICAL)
        self.author_lb = tk.Listbox(self.sel_author_frame, listvariable=tk.StringVar(value=authors),
                        height=4, yscrollcommand=scrollbar.set, font=self.controller.dynamic_font)
        scrollbar.config(command=self.author_lb.yview)
        self.author_lb.grid(row=0, column=0, sticky="nsew", padx=10)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=5)
        # Bind the listbox selection event to load commits
        self.author_lb.bind("<<ListboxSelect>>", lambda event: self.load_author_commits())

        
    def _create_select_commit_frame(self):
        """Create a frame to display the list of commits for the selected author."""
        self.author_commits = self.analyze_repository(author=self.author, max_commits=20)
        # Create a list of commit messages
        commit_messages = [
            f"{commit['sha'][:7]}: {commit['message']} ({commit['committed_date']})"
            for commit in self.author_commits
        ]
        # Create a list of commits
        self.commit_list_frame = ttk.Frame(self)
        self.commit_list_frame.grid_rowconfigure(0, weight=1)
        self.commit_list_frame.grid_columnconfigure(0, weight=1)
        scrollbar = tk.Scrollbar(self.commit_list_frame, orient=tk.VERTICAL)
        self.lb_commit = tk.Listbox(self.commit_list_frame, listvariable=tk.StringVar(value=commit_messages),
                        height=4, yscrollcommand=scrollbar.set,font=self.controller.dynamic_font)
        scrollbar.config(command=self.lb_commit.yview)
        self.lb_commit.grid(row=0, column=0, sticky="nsew", padx=10)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=5)
        

    def on_show(self):
        """Called by the controller when the frame is shown."""

        # Fingerprint label won't expand
        # Attributes display won't expand
        self.grid_rowconfigure(
            BUTTONS_ROW, weight=1, minsize=self.controller.font_size * 4
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
        self._set_ui_state(self.SELECT_PROJECT_FOLDER)


    def _set_ui_state(self, new_state):
        """Centralized method to manage UI frame visibility and related setup."""
        # Remove buttons from previous state
        for widget in self.grid_slaves(row=BUTTONS_ROW, column=0):
            widget.grid_forget()

        # Media display can be replaced by other widgets
        for widget in self.grid_slaves(row=MEDIA_ROW, column=0):
            widget.grid_forget()

        # Reset button row to default (can be overridden by specific states)
        self.grid_rowconfigure(BUTTONS_ROW, weight=1, minsize=self.controller.font_size * 4)

        if new_state == self.SELECT_PROJECT_FOLDER:
            self._update_attributes_display(
                "Step 1\n"
                "  Select a Git project folder to scan for commits."
            )
            self.sel_folder_frame.grid(
                row=BUTTONS_ROW, column=0, sticky="nsew", pady=10
            )
            self.media_display.grid(row=3, column=0, sticky="nsew")
            self.media_display.grid_propagate(False)
            self.media_display.load_default_image()
        elif new_state == self.SELECT_AUTHOR:
            self._create_select_author_frame()
            self._update_attributes_display(
                "Step 2\n"
                "  Select a commit author.\n\n"
                "    <Author>: <Commit Count>\n"
            )
            self.sel_author_btns_frame.grid(
                row=BUTTONS_ROW, column=0, sticky="nsew", pady=10
            )
            self.sel_author_frame.grid(
                row=MEDIA_ROW, column=0, sticky="nsew", pady=10
            )
        elif new_state == self.SCAN_PROJECT_COMMITS:
            self._create_select_commit_frame()
            self._update_attributes_display(
                "Step 3\n"
                "  Select a commit to sign."
            )
            self.commit_list_btns_frame.grid(
                row=BUTTONS_ROW, column=0, sticky="nsew", pady=10
            )
            self.commit_list_frame.grid(
                row=MEDIA_ROW, column=0, sticky="nsew", pady=10
            )
        elif new_state == self.EXPORT_COMMIT_QR:
            self._update_attributes_display(
                "Step 4\n"
                "  Scan the commit hash.\n\n"
                "  Scan back the commit signature."
            )
            self.commit_export_qr_btns_frame.grid(
                row=BUTTONS_ROW, column=0, sticky="nsew", pady=10
            )
            self.media_display.grid(row=MEDIA_ROW, column=0, sticky="nsew")
            self.media_display.grid_propagate(False)
            self.media_display.export_qr_code_image(self.commit_hash)


    def _update_attributes_display(self, content, state=tk.DISABLED):
        """Helper method to update the text widget."""
        if self.attributes_display:
            self.attributes_display.config(state=tk.NORMAL)
            self.attributes_display.delete(1.0, tk.END)
            self.attributes_display.insert(tk.END, content)
            self.attributes_display.config(state=state)

    def _sel_project_folder(self):
        """Select a project folder to scan for commits."""
        folder_path_str = filedialog.askdirectory(title="Select Git Project Folder")
        if not folder_path_str:
            return
        self.project_folder = Path(folder_path_str)
        # Check if the selected folder contains a Git repository
        if not (self.project_folder / ".git").exists():
            messagebox.showerror(
                "Invalid Folder",
                f"The selected folder does not contain a Git repository: {self.project_folder}",
            )
            return
        # Check if the repository contains any commits
        repo = Repo(self.project_folder)
        if not repo.head.is_valid():
            messagebox.showerror(
                "Empty Repository",
                f"The selected repository contains no commits: {self.project_folder}",
            )
            return
        # Check for authors
        authors = self._eval_commit_authors()
        if not authors:
            messagebox.showerror(
                "No Authors Found",
                f"The selected repository contains no commit authors: {self.project_folder}",
            )
            return

        self._set_ui_state(self.SELECT_AUTHOR)
    
    def _get_commit_info(self, repo: Repo, commit: Commit) -> dict:
        """Extract relevant commit information"""
        return {
            "sha": commit.hexsha,
            "author": str(commit.author),
            "message": commit.message.strip(),
            "committed_date": commit.committed_datetime.isoformat(),
            "parents": [p.hexsha for p in commit.parents],
            # "is_signed": check_commit_signature(repo.working_dir, commit.hexsha)
        }
    
    def analyze_repository(self, author=None, max_commits: int = 10): # -> List[dict]:
        """Analyze commits in a Git repository"""
        repo = Repo(self.project_folder)
        commits = []
        
        for commit in repo.iter_commits(max_count=max_commits):
            commit_info = self._get_commit_info(repo, commit)
            if author and commit_info["author"] != author:
                continue
            commits.append(commit_info)
        
        return commits
    
    def _eval_commit_authors(self):
        """
        List commit authors in the repository and count their commits.
        Returns a dict with authors and respective commits count.
        """
        repo = Repo(self.project_folder)
        authors = set()
        # Iterate over all commits in the repository        
        for commit in repo.iter_commits():
            authors.add(str(commit.author))
        # Count the number of commits for each author
        authors_count = {author: 0 for author in authors}
        for commit in repo.iter_commits():
            authors_count[str(commit.author)] += 1
        # Sort authors by number of commits
        sorted_authors = sorted(authors_count.items(), key=lambda x: x[1], reverse=True)

        return sorted_authors
    