import os
import cv2
from tkinter import ttk
import tkinter.messagebox as messagebox
from PIL import Image, ImageTk
from qrcode import QRCode
from pyzbar.pyzbar import decode

RESIZE_DELAY = 100  # milliseconds

class MediaDisplay(ttk.Frame):
    """
    A ttk.Frame subclass that can display a default image, generate and show QR codes,
    or stream and scan a live webcam feed.
    """

    def __init__(self, parent, default_image_name="GPGap.png", **kwargs):
        """
        Initialize the MediaDisplay frame.
        """
        super().__init__(parent, **kwargs)
        self.default_image_path = os.path.join(
            os.path.dirname(__file__), "assets", default_image_name
        )
        self.rowconfigure(0, weight=5)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        self.cap = None
        self.camera_running = False
        self.current_image = None
        self.qr_found = None
        # track scheduled update callback
        self.after_id = None

        # the area where we show images/QR/webcam
        self.media_label = ttk.Label(self, background="black")
        self.media_label.grid(row=0, column=0, sticky="nsew")

        # button to stop camera
        self.stop_scan_button = ttk.Button(
            self, text="Cancel Scan", command=self.stop_scan
        )
        self.current_image = None
        self.scaled_img = None
        
        self.resize_timer_id = None
        self.media_label.bind("<Configure>", self._resize_debounce)


    def _resize_debounce(self, event):
        """
        Debounce the resize event to avoid excessive calls to the resize function.
        """
        if self.resize_timer_id:
            self.after_cancel(self.resize_timer_id)
        self.resize_timer_id = self.after(RESIZE_DELAY, self._on_resize)
    
    def _on_resize(self):
        """
        Adjust the size of the media display area when the window is resized.
        """
        self.resize_timer_id = None
        if not (self.current_image):
            return
        img = self._resize_image_to_fit_label(self.current_image)
        self.scaled_img = ImageTk.PhotoImage(img)
        self.media_label.config(image=self.scaled_img, anchor="center")

    def _resize_image_to_fit_label(self, img):
        """
        Resize a PIL Image to fit inside the webcam_label while preserving aspect ratio.
        """
        self.update_idletasks()
        w = self.media_label.winfo_width()
        h = self.media_label.winfo_height()
        if w < 2 or h < 2:
            return img
        try:
            img_ratio = img.width / img.height
        except:
            return img
        lbl_ratio = w / h
        if lbl_ratio > img_ratio:
            new_h = h
            new_w = int(h * img_ratio)
        else:
            new_w = w
            new_h = int(w / img_ratio)
        return img.resize((new_w, new_h), Image.LANCZOS)

    def load_default_image(self):
        """
        Load and display the default image from assets or show a black placeholder on failure.
        """
        try:
            self.current_image = Image.open(self.default_image_path)
        except Exception:
            self.current_image = Image.new("RGB", (200, 200), "black")
        img = self._resize_image_to_fit_label(self.current_image)
        self.scaled_img = ImageTk.PhotoImage(img)
        self.media_label.config(image=self.scaled_img, anchor="center")

    def export_qr_code_image(self, qr_data: str) -> None:
        """
        Create a QR code from the provided data and display it in the label.
        """
        qr = QRCode()
        qr.add_data(qr_data)
        qr.make(fit=True)
        self.current_image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        img = self._resize_image_to_fit_label(self.current_image)
        img = ImageTk.PhotoImage(img)
        self.media_label.config(image=img, anchor="center")

    def start_scan(self):
        """
        Start capturing video from the default camera, show the cancel button,
        and begin the update loop to display frames.
        """
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showerror(
                "Camera Error",
                "Could not access webcam. Please check your camera connection and permissions.",
            )
            return

        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self.stop_scan_button.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.camera_running = True
        self.current_image = None
        self._update()

    def stop_scan(self):
        """
        Stop the webcam capture, hide the cancel button, release resources,
        and reload the default image.
        """
        self.camera_running = False
        if self.cap:
            self.cap.release()
        # cancel any pending update callbacks
        if self.after_id is not None:
            self.after_cancel(self.after_id)
            self.after_id = None
        self.stop_scan_button.grid_forget()
        self.load_default_image()

    def _update(self):
        """
        Internal method called periodically to grab a frame from the webcam,
        attempt QR code detection, and update the display.

        If a QR code is found, its data is stored in self.qr_found and the loop exits.
        Otherwise, the current frame is shown and the method reschedules itself.
        """
        if not self.camera_running:
            return
        ret, frame = self.cap.read()
        if ret:
            decoded = decode(frame)
            if decoded:
                self.qr_found = decoded[0].data.decode("utf-8")
                return
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb)
            img = self._resize_image_to_fit_label(img)
            self.scaled_image = ImageTk.PhotoImage(img)
            self.media_label.config(image=self.scaled_image, anchor="center")
        # schedule next frame update and keep its ID for cancellation
        self.after_id = self.after(30, self._update)

    def destroy(self):
        self.stop_scan()
        super().destroy()
