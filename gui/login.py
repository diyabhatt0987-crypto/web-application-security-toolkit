import os
import sys
import time

import customtkinter as ctk
from tkinter import messagebox


# Add the project folder so this file can be launched directly from any cwd.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.user.user import (  # noqa: E402
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_SECONDS,
    AuditLogger,
    Authenticator,
    UserManager,
)
from gui.visuals import (
    create_background_art,
    create_icon_badge,
    create_illustration,
)


BG_COLOR = "#071327"
CARD_COLOR = "#101E34"
CARD_BORDER = "#29415F"
TEXT_COLOR = "#f8fafc"
SECONDARY_TEXT = "#A8BCD4"
ACCENT = "#3B82F6"
ACCENT_HOVER = "#2563EB"
RED = "#FB7185"
DARK_BUTTON = "#243650"
DARK_BUTTON_HOVER = "#334B6C"


class LoginApp(ctk.CTk):
    """Welcome and login window for the security toolkit."""

    def __init__(self):
        super().__init__()

        self.title("Web Application Security Toolkit - Login")
        self.geometry("1080x720")
        self.minsize(900, 650)
        self.configure(fg_color=BG_COLOR)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.attempts = 0
        self.password_visible = False
        self.locked = False
        self.remaining_seconds = 0
        self.lock_after_id = None
        self.current_app = None

        try:
            self.audit = AuditLogger()
            self.user_manager = UserManager(self.audit)
            self.authenticator = Authenticator(self.user_manager, self.audit)
        except (OSError, ValueError) as error:
            messagebox.showerror(
                "Security Data Error",
                f"Could not load the security data:\n\n{error}",
                parent=self,
            )
            self.destroy()
            return

        self.show_welcome_screen()

    def _clear_screen(self):
        self.unbind("<Return>")
        if self.lock_after_id is not None:
            try:
                self.after_cancel(self.lock_after_id)
            except Exception:
                pass
            self.lock_after_id = None
        for widget in self.winfo_children():
            widget.destroy()

    def _make_card(self, relheight, relwidth=0.9):
        card = ctk.CTkFrame(
            self,
            fg_color=CARD_COLOR,
            corner_radius=20,
            border_width=1,
            border_color=CARD_BORDER,
        )
        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
            relwidth=relwidth,
            relheight=relheight,
        )
        return card

    def show_welcome_screen(self):
        self.locked = False
        self._clear_screen()
        create_background_art(self).place(
            relx=0,
            rely=0,
            relwidth=1,
            relheight=1,
        )
        card = self._make_card(0.82, relwidth=0.9)

        art_panel = ctk.CTkFrame(
            card,
            fg_color="#102743",
            corner_radius=18,
        )
        art_panel.place(relx=0, rely=0, relwidth=0.48, relheight=1)

        content_panel = ctk.CTkFrame(
            card,
            fg_color=CARD_COLOR,
            corner_radius=18,
        )
        content_panel.place(relx=0.48, rely=0, relwidth=0.52, relheight=1)

        create_illustration(
            art_panel,
            "welcome",
            width=420,
            height=270,
            bg="#102743"
        ).pack(pady=(70, 14))

        ctk.CTkLabel(
            art_panel,
            text="ASSESS  •  DETECT  •  PROTECT",
            font=("Arial", 15, "bold"),
            text_color="#4DE3F4",
        ).pack(pady=(3, 8))

        ctk.CTkLabel(
            art_panel,
            text="A clear view of your web security.",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT,
        ).pack()

        ctk.CTkLabel(
            content_panel,
            text="WELCOME",
            font=("Arial", 38, "bold"),
            text_color="#4DE3F4",
        ).pack(pady=(138, 10))

        ctk.CTkLabel(
            content_panel,
            text="Web Application\nSecurity Toolkit",
            font=("Arial", 25, "bold"),
            text_color=TEXT_COLOR,
            justify="center",
        ).pack(pady=6)

        ctk.CTkLabel(
            content_panel,
            text="Secure Web Application Assessment and Analysis",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT,
            wraplength=390,
            justify="center",
        ).pack(padx=25, pady=(8, 28))

        ctk.CTkButton(
            content_panel,
            text="LOGIN  →",
            width=280,
            height=56,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="white",
            font=("Arial", 15, "bold"),
            corner_radius=12,
            cursor="hand2",
            command=self.show_login_screen,
        ).pack()

    def show_login_screen(self):
        self.locked = False
        self.attempts = 0
        self.password_visible = False
        self._clear_screen()
        create_background_art(self).place(
            relx=0,
            rely=0,
            relwidth=1,
            relheight=1,
        )
        card = self._make_card(0.9, relwidth=0.9)

        art_panel = ctk.CTkFrame(
            card,
            fg_color="#102743",
            corner_radius=18,
        )
        art_panel.place(relx=0, rely=0, relwidth=0.42, relheight=1)

        form_panel = ctk.CTkFrame(
            card,
            fg_color=CARD_COLOR,
            corner_radius=18,
        )
        form_panel.place(relx=0.42, rely=0, relwidth=0.58, relheight=1)

        create_illustration(
            art_panel,
            "welcome",
            width=360,
            height=235,
            bg="#102743"
        ).pack(pady=(64, 18))

        ctk.CTkLabel(
            art_panel,
            text="YOUR SECURITY,\nIN CLEAR VIEW",
            font=("Arial", 23, "bold"),
            text_color="#4DE3F4",
            justify="center",
        ).pack(pady=(2, 10))

        ctk.CTkLabel(
            art_panel,
            text="Assess  •  Detect  •  Protect",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT,
        ).pack()

        title_row = ctk.CTkFrame(form_panel, fg_color="transparent")
        title_row.pack(pady=(42, 5))

        create_icon_badge(
            title_row,
            "security",
            accent="#4DE3F4",
            size=48,
            bg=CARD_COLOR
        ).pack(side="left", padx=(0, 12))

        ctk.CTkLabel(
            title_row,
            text="LOGIN",
            font=("Arial", 31, "bold"),
            text_color=TEXT_COLOR,
        ).pack(side="left")

        ctk.CTkLabel(
            form_panel,
            text="Enter your username and password",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT,
        ).pack(pady=(0, 22))

        ctk.CTkLabel(
            form_panel,
            text="Username",
            font=("Arial", 13, "bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", padx=48, pady=(0, 6))

        self.username_entry = ctk.CTkEntry(
            form_panel,
            width=400,
            height=46,
            placeholder_text="Enter username",
            font=("Arial", 13),
            corner_radius=10,
        )
        self.username_entry.pack(pady=(0, 15))

        ctk.CTkLabel(
            form_panel,
            text="Password",
            font=("Arial", 13, "bold"),
            text_color=TEXT_COLOR,
        ).pack(anchor="w", padx=48, pady=(0, 6))

        password_frame = ctk.CTkFrame(form_panel, fg_color="transparent")
        password_frame.pack(pady=(0, 8))

        self.password_entry = ctk.CTkEntry(
            password_frame,
            width=310,
            height=46,
            placeholder_text="Enter password",
            show="*",
            font=("Arial", 13),
            corner_radius=10,
        )
        self.password_entry.pack(side="left")

        self.show_password_button = ctk.CTkButton(
            password_frame,
            text="SHOW",
            width=78,
            height=46,
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON_HOVER,
            text_color="white",
            font=("Arial", 10, "bold"),
            corner_radius=10,
            command=self.toggle_password,
        )
        self.show_password_button.pack(side="left", padx=(8, 0))

        self.attempt_label = ctk.CTkLabel(
            form_panel,
            text="",
            font=("Arial", 11),
            text_color=SECONDARY_TEXT,
        )

        self.login_button = ctk.CTkButton(
            form_panel,
            text="LOGIN  →",
            width=280,
            height=52,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color="white",
            font=("Arial", 14, "bold"),
            corner_radius=12,
            command=self.login,
        )
        self.login_button.pack(pady=(8, 0))

        self.back_button = ctk.CTkButton(
            form_panel,
            text="BACK",
            width=180,
            height=42,
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON_HOVER,
            text_color="white",
            font=("Arial", 11, "bold"),
            corner_radius=10,
            command=self.show_welcome_screen,
        )
        self.back_button.pack(pady=(12, 0))

        self.username_entry.focus()
        self.bind("<Return>", lambda _event: self.login())

    def toggle_password(self):
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "*")
        self.show_password_button.configure(
            text="HIDE" if self.password_visible else "SHOW"
        )

    def login(self):
        if self.locked:
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning(
                "Missing Information",
                "Please enter username and password.",
                parent=self,
            )
            return

        state_entry = self.authenticator.state.get(username.casefold(), {})
        lock_until = (
            float(state_entry.get("lock_until", 0))
            if isinstance(state_entry, dict)
            else 0
        )
        if lock_until > time.time():
            self.remaining_seconds = int(lock_until - time.time()) + 1
            self.start_lockout(show_message=False)
            return

        user = self.authenticator.login(username, password)
        if user:
            messagebox.showinfo(
                "Login Successful",
                f"Welcome, {user.username}!\n"
                f"Role(s): {', '.join(user.roles)}",
                parent=self,
            )
            self.open_main_application(user)
            return

        self.password_entry.delete(0, "end")
        state_entry = self.authenticator.state.get(username.casefold(), {})
        lock_until = (
            float(state_entry.get("lock_until", 0))
            if isinstance(state_entry, dict)
            else 0
        )
        if lock_until > time.time():
            self.remaining_seconds = int(lock_until - time.time()) + 1
            self.start_lockout(show_message=True)
            return

        user_exists = self.user_manager.get_user(username) is not None
        failures = (
            int(state_entry.get("failures", 0))
            if isinstance(state_entry, dict)
            else 0
        )
        if user_exists:
            remaining = max(0, MAX_LOGIN_ATTEMPTS - failures)
            self._show_attempt_status(f"Attempts remaining: {remaining}")
        else:
            remaining = None

        error_text = "Incorrect username or password."
        if remaining is not None:
            error_text += f"\n\nAttempts remaining: {remaining}"
        messagebox.showerror("Login Failed", error_text, parent=self)

    def _show_attempt_status(self, text, color=SECONDARY_TEXT):
        if not self.attempt_label.winfo_manager():
            self.attempt_label.pack(pady=(0, 9), before=self.login_button)
        self.attempt_label.configure(text=text, text_color=color)

    def start_lockout(self, show_message=True):
        self.locked = True
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        self.login_button.configure(
            state="disabled",
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON,
        )
        self.show_password_button.configure(state="disabled")
        self._show_attempt_status("ACCOUNT LOCKED", color=RED)

        if show_message:
            minutes = max(1, (LOCKOUT_SECONDS + 59) // 60)
            messagebox.showerror(
                "Account Locked",
                "Too many incorrect login attempts.\n\n"
                f"Please wait {minutes} minutes before trying again.",
                parent=self,
            )
        self.update_lockout_timer()

    def update_lockout_timer(self):
        if not self.locked:
            return
        if self.remaining_seconds <= 0:
            self.end_lockout()
            return

        minutes, seconds = divmod(self.remaining_seconds, 60)
        self.attempt_label.configure(
            text=f"LOGIN LOCKED — try again in {minutes:02d}:{seconds:02d}",
            text_color=RED,
        )
        self.remaining_seconds -= 1
        self.lock_after_id = self.after(1000, self.update_lockout_timer)

    def end_lockout(self):
        self.locked = False
        self.remaining_seconds = 0
        self.attempts = 0
        self.username_entry.configure(state="normal")
        self.password_entry.configure(state="normal")
        self.login_button.configure(
            state="normal",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
        )
        self.show_password_button.configure(state="normal")
        self.attempt_label.pack_forget()
        self.lock_after_id = None
        messagebox.showinfo(
            "Login Unlocked",
            "The login system is available again.",
            parent=self,
        )

    def open_main_application(self, user):
        try:
            from gui.app import SecurityToolkitApp

            self.unbind("<Return>")
            self.current_app = SecurityToolkitApp(
                master=self,
                current_user=user,
                audit_logger=self.audit,
                user_manager=self.user_manager,
                authenticator=self.authenticator,
                login_window=self,
            )
            self.withdraw()
        except Exception as error:
            messagebox.showerror(
                "Application Error",
                f"Could not open the security dashboard:\n\n{error}",
                parent=self,
            )


if __name__ == "__main__":
    app = LoginApp()
    app.mainloop()
