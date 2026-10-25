import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import sys
import os
import threading
import json 
import time
from datetime import datetime
from urllib.parse import urlparse


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# SECURITY MODULES
# ============================================================

from modules.recon.recon import scan_target
from modules.security_config.security_config import check_security_config
from modules.vulnerability_assessment.vulnerability_assessment import (
    vulnerability_assessment
)
from modules.technology.techno import (
    check_waf_indicators,
    detect_technologies,
)
from modules.network.network_diagnostics import (
    check_open_ports,
    check_packet_loss,
)
from modules.website_audit.website_audit import crawl_website
from modules.recommendations.recomm import (
    generate_recommendations,
    format_recommendations,
)
from modules.user.user import (
    ROLE_PERMISSIONS,
    SESSION_TIMEOUT,
    ReferenceMonitor,
    User,
)
from gui.visuals import create_icon_badge, create_illustration


# ============================================================
# STORAGE
# ============================================================

HISTORY_FILE = os.path.join(
    PROJECT_ROOT, "gui_scan_history.json"
)

REPORTS_FOLDER = os.path.join(
    PROJECT_ROOT, "reports"
)

os.makedirs(REPORTS_FOLDER, exist_ok=True)


# ============================================================
# COLORS
# ============================================================

BG_COLOR = "#071327"
CARD_COLOR = "#101E34"
CARD_BORDER = "#29415F"

TEXT_COLOR = "#f8fafc"
SECONDARY_TEXT = "#A8BCD4"

ACCENT = "#3B82F6"
ACCENT_HOVER = "#2563EB"

GREEN = "#20D6B5"
GREEN_HOVER = "#12B89A"

ORANGE = "#F5B942"
ORANGE_HOVER = "#E69A24"

DARK_BUTTON = "#243650"
DARK_BUTTON_HOVER = "#334B6C"


# ============================================================
# MODULE REGISTRY
# ============================================================

MODULES = {
    "Reconnaissance": scan_target,
    "Website Crawl & Form Review": crawl_website,
    "Security Analysis": check_security_config,
    "Vulnerability Assessment": vulnerability_assessment,
    "Technology Detection": detect_technologies,
    "WAF / Firewall Indicators": check_waf_indicators,
    "Open Port Check": check_open_ports,
    "Packet Loss / Latency": check_packet_loss,
}

PROFILE_MODULES = {
    "Quick": ["Reconnaissance"],

    "Standard": [
        "Reconnaissance",
        "Security Analysis"
    ],

    "Deep": [
        "Reconnaissance",
        "Security Analysis",
        "Vulnerability Assessment",
        "Technology Detection",
        "Website Crawl & Form Review",
        "WAF / Firewall Indicators",
        "Open Port Check",
        "Packet Loss / Latency",
    ]
}

MODULE_PERMISSIONS = {
    "Reconnaissance": "recon",
    "Website Crawl & Form Review": "recon",
    "Security Analysis": "security_config",
    "Vulnerability Assessment": "vulnerability_assessment",
    # Technology detection is passive reconnaissance of public signals.
    "Technology Detection": "recon",
    "WAF / Firewall Indicators": "recon",
    "Open Port Check": "recon",
    "Packet Loss / Latency": "recon",
}


# ============================================================
# MAIN APPLICATION
# ============================================================

class SecurityToolkitApp(ctk.CTkToplevel):

    def __init__(
        self,
        master,
        current_user,
        audit_logger,
        user_manager,
        authenticator,
        login_window=None,
    ):
        super().__init__(master)

        self.title("Web Application Security Toolkit")
        self.geometry("1200x760")
        self.minsize(1000, 650)
        self.configure(fg_color=BG_COLOR)

        self.current_user = current_user
        self.audit = audit_logger
        self.user_manager = user_manager
        self.authenticator = authenticator
        self.reference_monitor = ReferenceMonitor(self.audit)
        self.login_window = login_window
        self.last_activity = time.time()
        self.session_check_after_id = None

        self.scanning = False

        self.current_results = {}
        self.current_target = ""
        self.current_scan_name = ""
        self.current_scan_time = ""
        self.current_report_path = ""
        self.current_json_path = ""
        self.current_profile = "Standard"

        self.scan_profile = ctk.StringVar(value="Standard")

        self.custom_modules = {
            name: ctk.BooleanVar(value=True)
            for name in MODULES
        }

        self.build_interface()
        self.bind("<Any-KeyPress>", self._record_activity)
        self.bind("<Any-Button>", self._record_activity)
        self.bind("<Motion>", self._record_activity)
        self.protocol("WM_DELETE_WINDOW", self.exit_application)
        self.session_check_after_id = self.after(
            15000,
            self._monitor_session
        )

    # ========================================================
    # BUILD INTERFACE
    # ========================================================

    def build_interface(self):

        self.top_bar = ctk.CTkFrame(
            self,
            fg_color=BG_COLOR,
            corner_radius=0
        )
        self.top_bar.pack(
            fill="x", padx=25, pady=(18, 8)
        )

        title_frame = ctk.CTkFrame(
            self.top_bar,
            fg_color="transparent"
        )
        title_frame.pack(
            side="left", fill="x", expand=True
        )

        create_icon_badge(
            title_frame,
            "security",
            accent="#4DE3F4",
            size=36,
            bg=BG_COLOR
        ).pack(side="left", padx=(0, 9))

        ctk.CTkLabel(
            title_frame,
            text="Web Application Security Toolkit",
            font=("Arial", 25, "bold"),
            text_color="#4DE3F4"
        ).pack(side="left")

        ctk.CTkLabel(
            title_frame,
            text="  |  Web Security Assessment Dashboard",
            font=("Arial", 12),
            text_color=SECONDARY_TEXT
        ).pack(side="left", padx=5, pady=(7, 0))

        if self.current_user.has_permission("view_scan_history"):
            self.create_button(
                self.top_bar,
                "DASHBOARD",
                ACCENT,
                ACCENT_HOVER,
                self.show_dashboard,
                side="right",
                width=12
            )

        if self.current_user.has_permission("view_reports"):
            self.create_button(
                self.top_bar,
                "REPORTS",
                ORANGE,
                ORANGE_HOVER,
                self.show_reports,
                side="right",
                width=10
            )

        if self.current_user.has_permission("view_scan_history"):
            self.create_button(
                self.top_bar,
                "RECOMMENDATIONS",
                GREEN,
                GREEN_HOVER,
                self.show_recommendations_history,
                side="right",
                width=16
            )

        self.account_bar = ctk.CTkFrame(
            self,
            fg_color=BG_COLOR,
            corner_radius=0
        )
        self.account_bar.pack(fill="x", padx=25, pady=(0, 4))

        self.create_button(
            self.account_bar,
            "MODULES",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.show_module_menu,
            side="right",
            width=10
        )

        ctk.CTkLabel(
            self.account_bar,
            text=(
                f"Signed in: {self.current_user.username}  |  "
                f"Role(s): {', '.join(self.current_user.roles)}"
            ),
            font=("Arial", 10),
            text_color=SECONDARY_TEXT
        ).pack(side="left", padx=4)

        self.create_button(
            self.account_bar,
            "SECURITY",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.show_security_menu,
            side="right",
            width=10
        )

        self.create_button(
            self.account_bar,
            "LOG OUT",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.logout,
            side="right",
            width=9
        )

        self.main = ctk.CTkFrame(
            self,
            fg_color=BG_COLOR,
            corner_radius=0
        )
        self.main.pack(
            fill="both", expand=True, padx=25, pady=8
        )

        self.show_module_menu()

    # ========================================================
    # SESSION AND PERMISSION CHECKS
    # ========================================================

    def _record_activity(self, _event=None):
        self.last_activity = time.time()

    def _monitor_session(self):
        if not self.winfo_exists():
            return

        if self.scanning:
            self.last_activity = time.time()

        if time.time() - self.last_activity >= SESSION_TIMEOUT:
            self._end_session(timed_out=True)
            return

        self.session_check_after_id = self.after(
            15000,
            self._monitor_session
        )

    def require_permission(self, permission, show_denial=True):
        if not self.winfo_exists():
            return False

        if time.time() - self.last_activity >= SESSION_TIMEOUT:
            self._end_session(timed_out=True)
            return False

        self.last_activity = time.time()
        allowed = self.reference_monitor.authorize(
            self.current_user,
            permission
        )

        if not allowed and show_denial:
            messagebox.showwarning(
                "Access Denied",
                f"Your role(s) do not allow this action: {permission}."
            )

        return allowed

    def _end_session(self, timed_out=False):
        if not self.winfo_exists():
            return

        if self.current_user:
            action = "SESSION_TIMEOUT" if timed_out else "LOGOUT"
            details = (
                "Session expired due to inactivity"
                if timed_out else "User logged out"
            )
            self.audit.log(self.current_user.username, action, details)

        if self.session_check_after_id:
            try:
                self.after_cancel(self.session_check_after_id)
            except Exception:
                pass
            self.session_check_after_id = None

        login_window = self.login_window
        self.destroy()

        if login_window and login_window.winfo_exists():
            login_window.deiconify()
            login_window.show_welcome_screen()
            if timed_out:
                messagebox.showinfo(
                    "Session Expired",
                    "You were logged out after 10 minutes of inactivity."
                )

    def logout(self):
        if self.scanning:
            messagebox.showwarning(
                "Scan In Progress",
                "Wait for the current scan to finish before logging out."
            )
            return
        self._end_session(timed_out=False)

    def exit_application(self):
        if self.scanning:
            messagebox.showwarning(
                "Scan In Progress",
                "Wait for the current scan to finish before exiting."
            )
            return

        if self.current_user:
            self.audit.log(
                self.current_user.username,
                "LOGOUT",
                "Application exited"
            )

        if self.session_check_after_id:
            try:
                self.after_cancel(self.session_check_after_id)
            except Exception:
                pass

        login_window = self.login_window
        self.destroy()
        if login_window and login_window.winfo_exists():
            login_window.destroy()

    def show_security_menu(self):
        self.clear_main()

        content = ctk.CTkScrollableFrame(
            self.main,
            fg_color=BG_COLOR,
            corner_radius=0,
            scrollbar_button_color=DARK_BUTTON,
            scrollbar_button_hover_color=DARK_BUTTON_HOVER
        )
        content.pack(fill="both", expand=True)

        hero = ctk.CTkFrame(
            content,
            fg_color=CARD_COLOR,
            corner_radius=16,
            border_width=1,
            border_color="#28647E"
        )
        hero.pack(fill="x", padx=5, pady=(2, 14))

        hero_copy = ctk.CTkFrame(hero, fg_color="transparent")
        hero_copy.pack(side="left", fill="both", expand=True, padx=22, pady=20)

        ctk.CTkLabel(
            hero_copy,
            text="Security and Account",
            font=("Arial", 27, "bold"),
            text_color="#4DE3F4"
        ).pack(anchor="w", pady=(4, 8))

        ctk.CTkLabel(
            hero_copy,
            text=(
                f"Welcome, {self.current_user.username}.  "
                f"Role: {', '.join(self.current_user.roles)}"
            ),
            font=("Arial", 14),
            text_color=SECONDARY_TEXT
        ).pack(anchor="w")

        create_illustration(
            hero,
            "welcome",
            width=265,
            height=125,
            bg=CARD_COLOR
        ).pack(side="right", padx=20, pady=10)

        action_items = []
        if self.current_user.has_permission("manage_users"):
            action_items.append((
                "Manage Users", "Add accounts and update roles.", "users",
                ACCENT, ACCENT_HOVER, "OPEN USERS", self.show_user_management
            ))
        if self.current_user.has_permission("change_own_password"):
            action_items.append((
                "Change My Password", "Update your account password.", "security",
                "#A78BFA", "#8B5CF6", "CHANGE PASSWORD", self.show_change_password
            ))
        if self.current_user.has_permission("view_audit_log"):
            action_items.append((
                "Audit Log / Integrity", "Review recorded security events.", "network",
                ORANGE, ORANGE_HOVER, "VIEW AUDIT LOG", self.show_audit_log
            ))
        if self.current_user.has_permission("run_rbac_test"):
            action_items.append((
                "RBAC Self-Test", "Check role-based access controls.", "scanner",
                GREEN, GREEN_HOVER, "RUN SELF-TEST", self.run_rbac_self_test
            ))
        if self.current_user.has_permission("generate_reports"):
            action_items.append((
                "Generate Current Report", "Create a report from the latest scan.", "technology",
                "#38D9EE", "#20B9D0", "GENERATE REPORT", self.generate_current_report
            ))

        action_items.extend([
            (
                "Log Out", "End this account session.", "security",
                DARK_BUTTON, DARK_BUTTON_HOVER, "LOG OUT", self.logout
            ),
            (
                "Exit Application", "Close the toolkit completely.", "warning",
                "#E45469", "#C93D53", "EXIT APP", self.exit_application
            ),
        ])

        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(fill="both", expand=True, padx=1, pady=(0, 12))
        for column in range(3):
            actions.grid_columnconfigure(column, weight=1, uniform="security-actions")

        for index, item in enumerate(action_items):
            title, description, icon, color, hover, button_text, command = item
            tile = ctk.CTkFrame(
                actions,
                fg_color=CARD_COLOR,
                corner_radius=15,
                border_width=1,
                border_color=color
            )
            tile.grid(
                row=index // 3,
                column=index % 3,
                sticky="nsew",
                padx=7,
                pady=7
            )

            heading = ctk.CTkFrame(tile, fg_color="transparent")
            heading.pack(fill="x", padx=14, pady=(15, 8))

            create_icon_badge(
                heading,
                icon,
                accent=color,
                size=48,
                bg=CARD_COLOR
            ).pack(side="left", padx=(0, 10))

            ctk.CTkLabel(
                heading,
                text=title,
                font=("Arial", 15, "bold"),
                text_color=TEXT_COLOR,
                wraplength=220,
                justify="left"
            ).pack(side="left", anchor="center")

            ctk.CTkLabel(
                tile,
                text=description,
                font=("Arial", 12),
                text_color=SECONDARY_TEXT,
                wraplength=320,
                justify="left"
            ).pack(anchor="w", padx=16, pady=(0, 12))

            ctk.CTkButton(
                tile,
                text=button_text,
                height=46,
                fg_color=color,
                hover_color=hover,
                text_color="white",
                font=("Arial", 11, "bold"),
                corner_radius=10,
                command=command
            ).pack(fill="x", padx=14, pady=(0, 14))

    def show_user_management(self):
        if not self.require_permission("manage_users"):
            return

        self.clear_main()
        ctk.CTkLabel(
            self.main, text="Manage Users", font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 10))

        content = ctk.CTkScrollableFrame(
            self.main, fg_color=CARD_COLOR, corner_radius=15
        )
        content.pack(fill="both", expand=True)

        users = list(self.user_manager.users.values())
        if not users:
            ctk.CTkLabel(
                content, text="No users are registered.",
                text_color=SECONDARY_TEXT
            ).pack(anchor="w", padx=16, pady=12)

        for user in users:
            card = ctk.CTkFrame(content, fg_color="#172033", corner_radius=10)
            card.pack(fill="x", padx=10, pady=6)
            status = "Active" if user.active else "Disabled"
            ctk.CTkLabel(
                card,
                text=f"{user.username}  |  {', '.join(user.roles)}  |  {status}",
                text_color=TEXT_COLOR,
                font=("Arial", 12, "bold")
            ).pack(side="left", padx=12, pady=12)
            self.create_button(
                card, "CHANGE ROLES", ACCENT, ACCENT_HOVER,
                lambda selected=user: self.edit_user_roles(selected)
            ).pack(side="right", padx=8, pady=7, ipady=4)
            if user.username.casefold() != "diya":
                self.create_button(
                    card, "REMOVE", "#991b1b", "#b91c1c",
                    lambda selected=user: self.remove_user(selected)
                ).pack(side="right", padx=4, pady=7, ipady=4)

        create_card = ctk.CTkFrame(content, fg_color="#172033", corner_radius=10)
        create_card.pack(fill="x", padx=10, pady=(14, 10))
        ctk.CTkLabel(
            create_card, text="Create User", font=("Arial", 16, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", padx=14, pady=(12, 6))

        form = ctk.CTkFrame(create_card, fg_color="transparent")
        form.pack(fill="x", padx=14, pady=(0, 8))
        self.new_username_entry = ctk.CTkEntry(
            form, placeholder_text="Username", width=220
        )
        self.new_username_entry.pack(side="left", padx=(0, 8), pady=4)
        self.new_user_password_entry = ctk.CTkEntry(
            form, placeholder_text="Password (8+ characters)", show="*", width=240
        )
        self.new_user_password_entry.pack(side="left", padx=8, pady=4)

        self.new_user_role_vars = {
            role: ctk.BooleanVar(value=(role == "viewer"))
            for role in ROLE_PERMISSIONS
        }
        role_row = ctk.CTkFrame(create_card, fg_color="transparent")
        role_row.pack(fill="x", padx=10, pady=(0, 8))
        for role, variable in self.new_user_role_vars.items():
            ctk.CTkCheckBox(
                role_row, text=role.replace("_", " "), variable=variable,
                text_color=TEXT_COLOR
            ).pack(side="left", padx=5, pady=4)

        self.create_button(
            create_card, "CREATE USER", ACCENT, ACCENT_HOVER,
            self.create_user_from_form
        ).pack(anchor="w", padx=14, pady=(0, 12), ipady=5, ipadx=8)

        self.create_button(
            self.main, "BACK", DARK_BUTTON, DARK_BUTTON_HOVER,
            self.show_security_menu
        ).pack(pady=8, ipady=5, ipadx=10)

    def create_user_from_form(self):
        if not self.require_permission("manage_users"):
            return

        username = self.new_username_entry.get().strip()
        password = self.new_user_password_entry.get()
        roles = [
            role for role, variable in self.new_user_role_vars.items()
            if variable.get()
        ]
        if not username or not password or not roles:
            messagebox.showwarning(
                "Missing Information",
                "Enter a username, password, and at least one role."
            )
            return
        if len(password) < 8:
            messagebox.showwarning(
                "Weak Password", "Password must contain at least 8 characters."
            )
            return
        if self.user_manager.get_user(username):
            messagebox.showerror(
                "User Exists", "A user with this username already exists."
            )
            return

        created = self.user_manager.create_user(
            self.current_user, username, password, roles
        )
        if created:
            messagebox.showinfo("User Created", f"User '{username}' was created.")
            self.show_user_management()
        else:
            messagebox.showerror("Could Not Create User", "Please check the username, password, and role selection.")

    def edit_user_roles(self, user):
        if not self.require_permission("manage_users"):
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Change roles: {user.username}")
        dialog.geometry("360x330")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(
            dialog, text=f"Roles for {user.username}",
            font=("Arial", 18, "bold"), text_color=TEXT_COLOR
        ).pack(anchor="w", padx=20, pady=(18, 10))
        role_vars = {
            role: ctk.BooleanVar(value=(role in user.roles))
            for role in ROLE_PERMISSIONS
        }
        for role, variable in role_vars.items():
            ctk.CTkCheckBox(
                dialog, text=role.replace("_", " "), variable=variable,
                text_color=TEXT_COLOR
            ).pack(anchor="w", padx=24, pady=5)

        def save_roles():
            roles = [role for role, variable in role_vars.items() if variable.get()]
            if not roles:
                messagebox.showwarning("Select a Role", "Choose at least one role.", parent=dialog)
                return
            updated = self.user_manager.change_roles(
                self.current_user, user.username, roles
            )
            if updated:
                dialog.destroy()
                self.show_user_management()
                messagebox.showinfo("Roles Updated", f"Roles for '{user.username}' were updated.")
            else:
                messagebox.showerror("Could Not Update Roles", "The primary admin must retain the admin role.", parent=dialog)

        self.create_button(
            dialog, "SAVE ROLES", ACCENT, ACCENT_HOVER, save_roles
        ).pack(anchor="w", padx=20, pady=16, ipady=5, ipadx=10)

    def remove_user(self, user):
        if not self.require_permission("manage_users"):
            return
        if not messagebox.askyesno(
            "Remove User", f"Remove user '{user.username}'?"
        ):
            return
        removed = self.user_manager.remove_user(
            self.current_user, user.username
        )
        if removed:
            messagebox.showinfo("User Removed", f"User '{user.username}' was removed.")
            self.show_user_management()
        else:
            messagebox.showerror("Could Not Remove User", "The user could not be removed.")

    def show_change_password(self):
        if not self.require_permission("change_own_password"):
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Change My Password")
        dialog.geometry("430x330")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(
            dialog, text="Change My Password", font=("Arial", 20, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", padx=22, pady=(20, 12))
        old_entry = ctk.CTkEntry(dialog, placeholder_text="Current password", show="*", width=350)
        old_entry.pack(padx=22, pady=7)
        new_entry = ctk.CTkEntry(dialog, placeholder_text="New password (8+ characters)", show="*", width=350)
        new_entry.pack(padx=22, pady=7)
        confirm_entry = ctk.CTkEntry(dialog, placeholder_text="Confirm new password", show="*", width=350)
        confirm_entry.pack(padx=22, pady=7)

        def change_password():
            old_password = old_entry.get()
            new_password = new_entry.get()
            confirm_password = confirm_entry.get()
            if not old_password or not new_password or not confirm_password:
                messagebox.showwarning("Missing Information", "Fill in all password fields.", parent=dialog)
                return
            if new_password != confirm_password:
                messagebox.showerror("Password Mismatch", "New passwords do not match.", parent=dialog)
                return
            if len(new_password) < 8:
                messagebox.showwarning("Weak Password", "New password must contain at least 8 characters.", parent=dialog)
                return
            changed = self.user_manager.change_password(
                self.current_user, old_password, new_password
            )
            if changed:
                dialog.destroy()
                messagebox.showinfo("Password Changed", "Your password was changed successfully.")
            else:
                messagebox.showerror("Password Not Changed", "Current password is incorrect or the new password is invalid.", parent=dialog)

        self.create_button(
            dialog, "UPDATE PASSWORD", ACCENT, ACCENT_HOVER,
            change_password
        ).pack(anchor="w", padx=22, pady=14, ipady=5, ipadx=10)

    def show_audit_log(self):
        if not self.require_permission("view_audit_log"):
            return

        self.clear_main()
        ctk.CTkLabel(
            self.main, text="Audit Log", font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 10))
        events_frame = ctk.CTkScrollableFrame(
            self.main, fg_color=CARD_COLOR, corner_radius=15
        )
        events_frame.pack(fill="both", expand=True)

        try:
            events = self.audit._read_events()
        except (OSError, ValueError) as error:
            messagebox.showerror("Audit Log Error", str(error))
            events = []

        if not events:
            ctk.CTkLabel(
                events_frame, text="No audit events recorded.",
                text_color=SECONDARY_TEXT
            ).pack(anchor="w", padx=15, pady=12)
        else:
            for event in reversed(events):
                card = ctk.CTkFrame(events_frame, fg_color="#172033", corner_radius=9)
                card.pack(fill="x", padx=8, pady=5)
                ctk.CTkLabel(
                    card,
                    text=f"{event.get('timestamp', '')}  |  {event.get('username', '')}  |  {event.get('action', '')}",
                    text_color=TEXT_COLOR, font=("Arial", 11, "bold")
                ).pack(anchor="w", padx=12, pady=(8, 3))
                ctk.CTkLabel(
                    card, text=event.get("details", ""), text_color=SECONDARY_TEXT,
                    wraplength=900, justify="left"
                ).pack(anchor="w", padx=12, pady=(0, 8))

        if self.current_user.has_permission("check_audit_integrity"):
            self.create_button(
                self.main, "CHECK AUDIT INTEGRITY", ORANGE, ORANGE_HOVER,
                self.check_audit_integrity
            ).pack(pady=8, ipady=5, ipadx=10)
        self.create_button(
            self.main, "BACK", DARK_BUTTON, DARK_BUTTON_HOVER,
            self.show_security_menu
        ).pack(pady=(0, 8), ipady=5, ipadx=10)

    def check_audit_integrity(self):
        if not self.require_permission("check_audit_integrity"):
            return
        try:
            valid, message = self.audit.verify_integrity()
        except (OSError, ValueError) as error:
            messagebox.showerror("Integrity Check Failed", str(error))
            return
        self.audit.log(
            self.current_user.username,
            "AUDIT_INTEGRITY_CHECK",
            f"Integrity={'VALID' if valid else 'FAILED'}; {message}"
        )
        if valid:
            messagebox.showinfo("Audit Integrity", f"VALID\n{message}")
        else:
            messagebox.showerror("Audit Integrity", f"FAILED\n{message}")
        self.show_audit_log()

    def run_rbac_self_test(self):
        if not self.require_permission("run_rbac_test"):
            return
        lines = []
        for role, permissions in ROLE_PERMISSIONS.items():
            test_user = User(
                username=f"test_{role}", salt="00", password_hash="", roles=[role]
            )
            lines.append(f"{role.replace('_', ' ').title()}")
            for permission in sorted(permissions):
                lines.append(f"  ALLOW  {permission}")
            denied = {"manage_users", "run_scan", "view_reports"} - permissions
            for permission in sorted(denied):
                lines.append(f"  DENY   {permission}")
            assert all(test_user.has_permission(item) for item in permissions)

        self.audit.log(
            self.current_user.username,
            "RBAC_SELF_TEST",
            "Role-permission checks passed"
        )
        self.clear_main()
        ctk.CTkLabel(
            self.main, text="RBAC Self-Test Passed", font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 10))
        output = ctk.CTkTextbox(self.main, fg_color=CARD_COLOR, text_color=TEXT_COLOR)
        output.pack(fill="both", expand=True)
        output.insert("1.0", "\n".join(lines))
        output.configure(state="disabled")
        self.create_button(
            self.main, "BACK", DARK_BUTTON, DARK_BUTTON_HOVER,
            self.show_security_menu
        ).pack(pady=8, ipady=5, ipadx=10)

    def generate_current_report(self):
        if not self.require_permission("generate_reports"):
            return
        if not self.current_results or not self.current_target:
            messagebox.showwarning(
                "No Current Results", "Run a scan before generating a report."
            )
            return
        self.current_report_path = self.create_security_report(
            self.current_scan_name, self.current_target, self.current_results
        )
        if self.current_report_path:
            self.audit.log(
                self.current_user.username,
                "GENERATE_REPORT",
                self.current_report_path
            )
            messagebox.showinfo(
                "Report Generated", f"Report created at:\n\n{self.current_report_path}"
            )
        else:
            messagebox.showerror("Report Error", "The report could not be generated.")

    # ========================================================
    # REUSABLE BUTTON
    # ========================================================

    def create_button(
        self,
        parent,
        text,
        bg,
        hover,
        command,
        side=None,
        width=None
    ):

        button = tk.Button(
            parent,
            text=text,
            width=width,
            height=2,
            bg=bg,
            fg="white",
            activebackground=hover,
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Arial", 11, "bold"),
            command=command
        )

        if side:
            button.pack(
                side=side, padx=5, ipady=8
            )

        return button

    # ========================================================
    # CLEAR MAIN
    # ========================================================

    def clear_main(self):

        for widget in self.main.winfo_children():
            widget.destroy()

    # ========================================================
    # HOME SCREEN
    # ========================================================

 
    def show_module_menu(self):
        if self.scanning:
            messagebox.showwarning(
                "Scan In Progress",
                "Wait for the current scan to finish before changing modules."
            )
            return

        self.clear_main()

        content = ctk.CTkFrame(
            self.main,
            fg_color="transparent"
        )
        content.pack(fill="both", expand=True, padx=8, pady=18)

        ctk.CTkLabel(
            content,
            text="Choose a Module",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", padx=12, pady=(12, 4))

        ctk.CTkLabel(
            content,
            text="Choose Layers or open the other security modules.",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT
        ).pack(anchor="w", padx=12, pady=(0, 18))

        cards_frame = ctk.CTkFrame(
            content,
            fg_color="transparent"
        )
        cards_frame.pack(fill="x", padx=6, pady=8)

        if self.current_user.has_permission("run_scan"):
            self.create_module_card(
                cards_frame,
                "Layers",
                "Choose website security layers and run a separate layer scan.",
                self.show_layer_scanner,
                visual="layers",
                accent="#A78BFA"
            )

        self.create_module_card(
            cards_frame,
            "Other Modules",
            "Open reconnaissance, security analysis, vulnerability assessment, and related tools.",
            self.show_home,
            visual="scanner",
            accent="#38D9EE"
        )

    def show_layer_scanner(self):
        if not self.require_permission("run_scan"):
            return

        self.clear_main()

        from gui.layers import LayerScannerApp

        self.layer_view = LayerScannerApp(
            self.main,
            on_back=self.show_module_menu,
            on_scan_state=self._set_layer_scan_state
        )
        self.layer_view.pack(fill="both", expand=True)

    def _set_layer_scan_state(self, scanning):
        self.scanning = scanning
        if scanning:
            self.last_activity = time.time()

    def show_home(self):
        self.clear_main()
        can_scan = self.current_user.has_permission("run_scan")

        # Scrollable home screen
        content = ctk.CTkScrollableFrame(
            self.main,
            fg_color=BG_COLOR,
            corner_radius=0,
            scrollbar_button_color=DARK_BUTTON,
            scrollbar_button_hover_color=DARK_BUTTON_HOVER
        )
        content.pack(fill="both", expand=True)

        hero_card = ctk.CTkFrame(
            content,
            fg_color=CARD_COLOR,
            corner_radius=15,
            border_width=1,
            border_color="#28647E"
        )
        hero_card.pack(fill="x", pady=(0, 12))

        hero_copy = ctk.CTkFrame(hero_card, fg_color="transparent")
        hero_copy.pack(side="left", fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(
            hero_copy,
            text="Security Scan Workspace",
            font=("Arial", 21, "bold"),
            text_color="#4DE3F4"
        ).pack(anchor="w", pady=(3, 6))

        ctk.CTkLabel(
            hero_copy,
            text="Choose a target and run the checks you need.",
            font=("Arial", 12),
            text_color=SECONDARY_TEXT
        ).pack(anchor="w")

        create_illustration(
            hero_card,
            "scanner",
            width=260,
            height=112,
            bg=CARD_COLOR
        ).pack(side="right", padx=18, pady=10)

        # Target card
        target_card = ctk.CTkFrame(
            content,
            fg_color=CARD_COLOR,
            corner_radius=15,
            border_width=1,
            border_color=CARD_BORDER
        )
        target_card.pack(fill="x", pady=(0, 12))

        target_heading = ctk.CTkFrame(target_card, fg_color="transparent")
        target_heading.pack(anchor="w", padx=18, pady=(12, 4))

        create_icon_badge(
            target_heading,
            "network",
            accent="#38D9EE",
            size=34,
            bg=CARD_COLOR
        ).pack(side="left", padx=(0, 9))

        ctk.CTkLabel(
            target_heading,
            text="Target Website",
            font=("Arial", 18, "bold"),
            text_color=TEXT_COLOR
        ).pack(side="left")

        ctk.CTkLabel(
            target_card,
            text="Only scan websites you own or have permission to assess.",
            font=("Arial", 12),
            text_color=SECONDARY_TEXT
        ).pack(anchor="w", padx=20, pady=(0, 10))

        url_frame = ctk.CTkFrame(
            target_card,
            fg_color="transparent"
        )
        url_frame.pack(fill="x", padx=20, pady=(0, 15))

        self.url_entry = ctk.CTkEntry(
            url_frame,
            height=40,
            placeholder_text="https://example.com",
            font=("Arial", 13)
        )
        self.url_entry.pack(
            side="left", fill="x", expand=True, padx=(0, 10)
        )

        enter_button = self.create_button(
            url_frame,
            "ENTER",
            ACCENT,
            ACCENT_HOVER,
            self.enter_target,
            width=12
        )
        enter_button.pack_configure(ipady=7)
        if not can_scan:
            self.url_entry.configure(state="disabled")
            enter_button.configure(state="disabled")

        # Scan profiles
        profile_card = ctk.CTkFrame(
            content,
            fg_color=CARD_COLOR,
            corner_radius=15,
            border_width=1,
            border_color=CARD_BORDER
        )
        profile_card.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            profile_card,
            text="Scan Profile",
            font=("Arial", 17, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", padx=20, pady=(10, 4))

        ctk.CTkLabel(
            profile_card,
            text=(
                "Quick: Recon only  |  Standard: Recon + Security Analysis\n"
                "Deep: All modules  |  Custom: Choose modules below"
            ),
            font=("Arial", 11),
            text_color=SECONDARY_TEXT,
            justify="left"
        ).pack(anchor="w", padx=20, pady=(0, 8))

        self.profile_menu = ctk.CTkOptionMenu(
            profile_card,
            values=["Quick", "Standard", "Deep", "Custom"],
            variable=self.scan_profile,
            command=self.update_custom_options,
            width=200
        )
        self.profile_menu.pack(anchor="w", padx=20, pady=(0, 8))
        if not can_scan:
            self.profile_menu.configure(state="disabled")

        self.custom_frame = ctk.CTkFrame(
            profile_card,
            fg_color="transparent"
        )

        for name, variable in self.custom_modules.items():
            if not self.current_user.has_permission(MODULE_PERMISSIONS[name]):
                continue
            ctk.CTkCheckBox(
                self.custom_frame,
                text=name,
                variable=variable,
                text_color=TEXT_COLOR
            ).pack(anchor="w", padx=20, pady=3)

        self.update_custom_options(self.scan_profile.get())

        # Show only the scan actions allowed for this account.
        available_cards = []
        if self.current_user.has_permission("recon"):
            available_cards.extend([
                ("Reconnaissance", "Collect basic information about the target.", self.run_recon),
                ("Website Crawl & Form Review", "Review a limited set of same-domain pages, links, and forms without submitting them.", self.run_website_crawl),
                ("Technology Detection", "Identify public web technologies and CDN services.", self.run_technology),
                ("WAF / Firewall Indicators", "Look for public WAF and edge-protection signals. Indicators are not proof of firewall coverage.", self.run_waf_indicators),
                ("Open Port Check", "Check a fixed list of common TCP ports on the target's resolved public IP.", self.run_open_ports),
                ("Packet Loss / Latency", "Send four ICMP ping requests and summarize replies and latency.", self.run_packet_loss),
            ])
        if self.current_user.has_permission("security_config"):
            available_cards.append((
                "Security Analysis", "Analyze HTTPS, headers and cookie security.", self.run_security
            ))
        if self.current_user.has_permission("vulnerability_assessment"):
            available_cards.append((
                "Vulnerability Assessment", "Check common security configuration issues.", self.run_vulnerability
            ))
        if self.current_user.has_permission("run_scan"):
            available_cards.append((
                "Full Assessment", "Run the modules allowed for your role.", self.start_full_scan
            ))

        if available_cards:
            ctk.CTkLabel(
                content,
                text="Security Modules",
                font=("Arial", 20, "bold"),
                text_color=TEXT_COLOR
            ).pack(anchor="w", pady=(0, 8))

            modules_frame = ctk.CTkFrame(content, fg_color="transparent")
            modules_frame.pack(fill="x", pady=(0, 12))
            for start in range(0, len(available_cards), 2):
                row = ctk.CTkFrame(modules_frame, fg_color="transparent")
                row.pack(fill="x", pady=(0, 8))
                for title, description, command in available_cards[start:start + 2]:
                    self.create_module_card(row, title, description, command)
        else:
            ctk.CTkLabel(
                content,
                text="Your account can view reports and scan history. Scan access is not enabled for your role.",
                font=("Arial", 13),
                text_color=SECONDARY_TEXT,
                wraplength=900,
                justify="left"
            ).pack(anchor="w", pady=16)

    # ========================================================
    # PROFILE OPTIONS
    # ========================================================

    def update_custom_options(self, choice):

        if choice == "Custom":
            self.custom_frame.pack(
                fill="x", padx=5, pady=(0, 10)
            )
        else:
            self.custom_frame.pack_forget()

    def get_selected_modules(self):

        profile = self.scan_profile.get()

        if profile == "Custom":
            requested = [
                name for name, variable in self.custom_modules.items()
                if variable.get()
            ]
            if not requested:
                messagebox.showwarning(
                    "No Modules Selected",
                    "Select at least one module for Custom Scan."
                )
                return None
        else:
            requested = PROFILE_MODULES[profile][:]

        allowed = [
            name for name in requested
            if self.current_user.has_permission(MODULE_PERMISSIONS[name])
        ]
        if not allowed:
            messagebox.showwarning(
                "No Available Modules",
                "Your role does not allow any modules in this profile."
            )
            return None

        for name in allowed:
            if not self.require_permission(
                MODULE_PERMISSIONS[name],
                show_denial=False
            ):
                return None

        skipped = [name for name in requested if name not in allowed]
        if skipped:
            messagebox.showinfo(
                "Role-Based Access",
                "These modules are not enabled for your role and will be skipped:\n\n"
                + "\n".join(skipped)
            )
        return allowed

    # ========================================================
    # MODULE CARD
    # ========================================================

    def create_module_card(
        self,
        parent,
        title,
        description,
        command,
        visual=None,
        accent=None
    ):

        icon_kinds = {
            "Layers": "layers",
            "Other Modules": "scanner",
            "Reconnaissance": "recon",
            "Website Crawl & Form Review": "scanner",
            "Technology Detection": "technology",
            "WAF / Firewall Indicators": "security",
            "Open Port Check": "network",
            "Packet Loss / Latency": "network",
            "Security Analysis": "security",
            "Vulnerability Assessment": "vulnerability",
            "Full Assessment": "scanner",
        }
        accents = {
            "Layers": "#A78BFA",
            "Other Modules": "#38D9EE",
            "Reconnaissance": "#38D9EE",
            "Website Crawl & Form Review": "#A78BFA",
            "Technology Detection": "#60A5FA",
            "WAF / Firewall Indicators": "#F5B942",
            "Open Port Check": "#20D6B5",
            "Packet Loss / Latency": "#FB7185",
            "Security Analysis": "#20D6B5",
            "Vulnerability Assessment": "#F5B942",
            "Full Assessment": "#A78BFA",
        }
        accent = accent or accents.get(title, ACCENT)

        card = ctk.CTkFrame(
            parent,
            fg_color=CARD_COLOR,
            corner_radius=15,
            border_width=1,
            border_color=accent
        )
        card.pack(
            side="left", fill="both", expand=True, padx=6
        )

        if visual:
            create_illustration(
                card,
                visual,
                width=310,
                height=112,
                bg=CARD_COLOR
            ).pack(anchor="w", padx=14, pady=(14, 8))

        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.pack(fill="x", padx=15, pady=(14, 6))

        create_icon_badge(
            title_row,
            icon_kinds.get(title, "security"),
            accent=accent,
            size=40,
            bg=CARD_COLOR
        ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(
            title_row,
            text=title,
            font=("Arial", 16, "bold"),
            text_color=TEXT_COLOR,
            wraplength=260,
            justify="left"
        ).pack(side="left", anchor="center")

        ctk.CTkLabel(
            card,
            text=description,
            font=("Arial", 11),
            text_color=SECONDARY_TEXT,
            wraplength=300,
            justify="left"
        ).pack(anchor="w", padx=15, pady=(0, 12))

        self.create_button(
            card,
            "OPEN",
            ACCENT,
            ACCENT_HOVER,
            command,
            width=15
        ).pack_configure(pady=(0, 15), ipady=5)

    # ========================================================
    # GET AND VALIDATE TARGET
    # ========================================================

    def get_target(self):

        target = self.url_entry.get().strip()

        if not target:
            messagebox.showwarning(
                "Target Required",
                "Please enter a website URL first."
            )
            return None

        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or any(char.isspace() for char in target)
            or parsed.username is not None
            or parsed.password is not None
        ):
            messagebox.showerror(
                "Invalid URL",
                "Enter a valid URL, such as https://example.com."
            )
            return None

        try:
            _ = parsed.port
        except ValueError:
            messagebox.showerror(
                "Invalid URL",
                "The website URL contains an invalid port number."
            )
            return None

        return target

    def confirm_authorization(self, target):

        return messagebox.askyesno(
            "Authorization Required",
            "Confirm that you own this website or have explicit "
            "permission to assess it.\n\n"
            f"Target: {target}\n\n"
            "Continue?"
        )

    def enter_target(self):

        target = self.get_target()

        if target:
            messagebox.showinfo(
                "Target Accepted",
                f"Target URL:\n\n{target}"
            )

    # ========================================================
    # INDIVIDUAL MODULES
    # ========================================================

    def run_recon(self):

        self.run_single_scan(
            "Reconnaissance",
            scan_target
        )

    def run_website_crawl(self):
        self.run_single_scan(
            "Website Crawl & Form Review",
            crawl_website
        )

    def run_security(self):

        self.run_single_scan(
            "Security Analysis",
            check_security_config
        )

    def run_vulnerability(self):

        self.run_single_scan(
            "Vulnerability Assessment",
            vulnerability_assessment
        )
    def run_technology(self):
        self.run_single_scan(
            "Technology Detection",
            detect_technologies
        )

    def run_waf_indicators(self):
        self.run_single_scan(
            "WAF / Firewall Indicators",
            check_waf_indicators
        )

    def run_open_ports(self):
        self.run_single_scan(
            "Open Port Check",
            check_open_ports
        )

    def run_packet_loss(self):
        self.run_single_scan(
            "Packet Loss / Latency",
            check_packet_loss
        )

    # ========================================================
    # START SINGLE SCAN
    # ========================================================

    def run_single_scan(self, scan_name, function):

        permission = MODULE_PERMISSIONS.get(scan_name)
        if not permission or not self.require_permission(permission):
            return

        if self.scanning:
            messagebox.showinfo(
                "Scan Running",
                "A scan is already running."
            )
            return

        target = self.get_target()

        if not target:
            return

        if not self.confirm_authorization(target):
            return

        self.scanning = True
        self.current_scan_name = scan_name
        self.current_target = target
        self.current_profile = self.scan_profile.get()
        self.current_scan_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.current_json_path = ""
        self.audit.log(
            self.current_user.username,
            "SCAN_STARTED",
            f"{scan_name}; target={target}"
        )

        self.show_loading(
            f"Running {scan_name}..."
        )

        threading.Thread(
            target=self.single_scan_worker,
            args=(scan_name, function, target),
            daemon=True
        ).start()

    def single_scan_worker(
        self,
        scan_name,
        function,
        target
    ):

        try:
            if function is crawl_website:
                result = function(
                    target,
                    progress_callback=lambda completed, maximum, url: self.after(
                        0,
                        lambda c=completed, m=maximum, u=url:
                            self.update_scan_progress(c, m, u)
                    ),
                )
            else:
                result = function(target)

            self.after(
                0,
                lambda: self.single_scan_finished(
                    scan_name, result
                )
            )

        except Exception as error:
            error_message = str(error)
            self.after(
                0,
                lambda: self.scan_error(error_message)
            )

    def single_scan_finished(self, scan_name, result):

        self.scanning = False

        if result is None:
            self.audit.log(
                self.current_user.username,
                "SCAN_FAILED",
                f"{scan_name}; target={self.current_target}"
            )
            messagebox.showerror(
                "Scan Failed",
                f"{scan_name} could not complete. "
                "Check the target and network connection."
            )
            self.show_home()
            return

        self.current_results = {
            scan_name: result
        }

        self.finish_and_save_scan()

    # ========================================================
    # FULL ASSESSMENT
    # ========================================================

    def start_full_scan(self):

        if not self.require_permission("run_scan"):
            return

        if self.scanning:
            messagebox.showinfo(
                "Scan Running",
                "A scan is already running."
            )
            return

        target = self.get_target()

        if not target:
            return

        selected_modules = self.get_selected_modules()

        if not selected_modules:
            return

        if not self.confirm_authorization(target):
            return

        self.scanning = True
        self.current_target = target
        self.current_profile = self.scan_profile.get()
        self.current_scan_name = "Full Assessment"
        self.current_scan_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.current_json_path = ""
        self.audit.log(
            self.current_user.username,
            "SCAN_STARTED",
            f"Full Assessment ({', '.join(selected_modules)}); target={target}"
        )

        self.show_loading(
            f"Running {self.current_profile} Assessment..."
        )

        threading.Thread(
            target=self.full_scan_worker,
            args=(target, selected_modules),
            daemon=True
        ).start()

    def full_scan_worker(self, target, selected_modules):

        results = {}

        try:
            for module_name in selected_modules:

                function = MODULES[module_name]

                print(f"\n[GUI] Running {module_name}...")

                if function is crawl_website:
                    result = function(
                        target,
                        progress_callback=lambda completed, maximum, url: self.after(
                            0,
                            lambda c=completed, m=maximum, u=url:
                                self.update_scan_progress(c, m, u)
                        ),
                    )
                else:
                    result = function(target)

                if result is None:
                    results[module_name] = {
                        "Error": (
                            "This module could not complete. "
                            "Check the network connection or target."
                        )
                    }
                else:
                    results[module_name] = result

            self.after(
                0,
                lambda: self.full_scan_finished(results)
            )

        except Exception as error:
            error_message = str(error)
            self.after(
                0,
                lambda: self.scan_error(error_message)
            )

    def full_scan_finished(self, results):

        self.scanning = False
        self.current_results = results

        self.finish_and_save_scan()

    # ========================================================
    # SAVE RESULTS AND GENERATE REPORT
    # ========================================================

    def finish_and_save_scan(self):

        self.current_report_path = ""
        self.current_json_path = ""
        if self.require_permission("generate_reports", show_denial=False):
            self.current_report_path = self.create_security_report(
                self.current_scan_name,
                self.current_target,
                self.current_results
            )
            if self.current_report_path:
                self.audit.log(
                    self.current_user.username,
                    "GENERATE_REPORT",
                    self.current_report_path
                )

        self.save_scan_to_history(
            self.current_scan_name,
            self.current_target,
            self.current_results,
            self.current_report_path
        )
        self.audit.log(
            self.current_user.username,
            "SCAN_COMPLETED",
            f"{self.current_scan_name}; target={self.current_target}"
        )

        self.show_current_scan()

    # ========================================================
    # LOADING SCREEN
    # ========================================================

    def show_loading(self, message):

        self.clear_main()

        card = ctk.CTkFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=15
        )
        card.pack(fill="both", expand=True)

        ctk.CTkLabel(
            card,
            text=message,
            font=("Arial", 22, "bold"),
            text_color=TEXT_COLOR
        ).pack(pady=(180, 15))

        self.loading_status_label = ctk.CTkLabel(
            card,
            text="Please wait...",
            font=("Arial", 13),
            text_color=SECONDARY_TEXT
        )
        self.loading_status_label.pack()

    def update_scan_progress(self, completed, maximum, url):
        label = getattr(self, "loading_status_label", None)
        if not label or not label.winfo_exists():
            return
        path = urlparse(url).path or "/"
        label.configure(
            text=f"Reviewing page {completed} of up to {maximum}: {path}"
        )

    # ========================================================
    # CURRENT SCAN RESULTS
    # ========================================================

    def show_current_scan(self):

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text=f"Current Scan: {self.current_scan_name}",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            self.main,
            text=(
                f"Target: {self.current_target}\n"
                f"Profile: {self.current_profile}\n"
                f"Time: {self.current_scan_time}"
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT,
            justify="left"
        ).pack(anchor="w", pady=(0, 12))

        frame = ctk.CTkScrollableFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=15
        )
        frame.pack(fill="both", expand=True)

        self.display_results(frame, self.current_results)

        actions = ctk.CTkFrame(
            self.main, fg_color="transparent"
        )
        actions.pack(pady=10)

        self.create_button(
            actions, "CURRENT DASHBOARD",
            ACCENT, ACCENT_HOVER,
            self.show_current_dashboard
        ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)

        if self.current_user.has_permission("generate_reports"):
            self.create_button(
                actions, "DOWNLOAD DASHBOARD",
                GREEN, GREEN_HOVER,
                self.download_current_dashboard
            ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)
            self.create_button(
                actions, "EXPORT JSON",
                "#A78BFA", "#8B5CF6",
                self.export_current_scan_json
            ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)

        if self.current_report_path and self.current_user.has_permission("view_reports"):
            self.create_button(
                actions, "DOWNLOAD REPORT",
                ORANGE, ORANGE_HOVER,
                lambda: self.download_report(
                    self.current_report_path
                )
            ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)

        if self.current_user.has_permission("view_scan_history"):
            self.create_button(
                actions, "RECOMMENDATIONS",
                GREEN, GREEN_HOVER,
                lambda: self.ask_recommendation_mode(
                    self.current_results,
                    self.current_scan_name,
                    self.current_target,
                    self.current_scan_time,
                    back_command=self.show_current_scan
                )
            ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)

        self.create_button(
            actions, "BACK TO HOME",
            DARK_BUTTON, DARK_BUTTON_HOVER,
            self.show_home
        ).pack_configure(side="left", padx=4, ipady=7, ipadx=5)

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    def display_results(self, parent, data, level=0):

        if isinstance(data, dict):

            for key, value in data.items():

                ctk.CTkLabel(
                    parent,
                    text=str(key),
                    font=("Arial", 14, "bold"),
                    text_color=TEXT_COLOR
                ).pack(
                    anchor="w",
                    padx=20 + level * 15,
                    pady=(10, 3)
                )

                if isinstance(value, (dict, list)):
                    self.display_results(
                        parent, value, level + 1
                    )
                else:
                    ctk.CTkLabel(
                        parent,
                        text=str(value),
                        font=("Arial", 12),
                        text_color=SECONDARY_TEXT,
                        wraplength=900,
                        justify="left"
                    ).pack(
                        anchor="w",
                        padx=35 + level * 15,
                        pady=(0, 4)
                    )

        elif isinstance(data, list):

            for item in data:
                self.display_results(parent, item, level)

        else:
            ctk.CTkLabel(
                parent,
                text=str(data),
                font=("Arial", 12),
                text_color=SECONDARY_TEXT,
                wraplength=900,
                justify="left"
            ).pack(
                anchor="w",
                padx=35 + level * 15,
                pady=3
            )

    # ========================================================
    # SUMMARY CALCULATION
    # ========================================================

    def calculate_summary(self, data):

        counts = {
            "PASS": 0,
            "WARNING": 0,
            "INFO": 0,
            "MISSING": 0
        }

        def walk(value):

            if isinstance(value, dict):
                for item in value.values():
                    walk(item)

            elif isinstance(value, list):
                for item in value:
                    walk(item)

            elif isinstance(value, str):

                upper = value.upper()

                if "PASS" in upper:
                    counts["PASS"] += 1

                if "WARNING" in upper:
                    counts["WARNING"] += 1

                if "INFO" in upper:
                    counts["INFO"] += 1

                if "MISSING" in upper:
                    counts["MISSING"] += 1

        walk(data)
        return counts

    def create_summary_card(self, parent, summary):

        card = ctk.CTkFrame(
            parent,
            fg_color="#172033",
            corner_radius=12
        )
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            card,
            text="Security Summary",
            font=("Arial", 18, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", padx=20, pady=(15, 8))

        ctk.CTkLabel(
            card,
            text=(
                f"PASS: {summary['PASS']}     "
                f"WARNING: {summary['WARNING']}     "
                f"INFO: {summary['INFO']}     "
                f"MISSING: {summary['MISSING']}"
            ),
            font=("Arial", 13, "bold"),
            text_color=TEXT_COLOR
        ).pack(padx=20, pady=(0, 15))

    # ========================================================
    # CURRENT DASHBOARD
    # ========================================================

    def show_current_dashboard(self):

        if not self.require_permission("view_reports"):
            return

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text="Current Scan Dashboard",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            self.main,
            text=(
                f"Target: {self.current_target}\n"
                f"Scan: {self.current_scan_name}\n"
                f"Profile: {self.current_profile}\n"
                f"Time: {self.current_scan_time}"
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT,
            justify="left"
        ).pack(anchor="w", pady=(0, 12))

        frame = ctk.CTkScrollableFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=15
        )
        frame.pack(fill="both", expand=True)

        self.create_summary_card(
            frame,
            self.calculate_summary(self.current_results)
        )
        self.display_results(frame, self.current_results)

        self.create_button(
            self.main,
            "DOWNLOAD DASHBOARD",
            GREEN,
            GREEN_HOVER,
            self.download_current_dashboard
        ).pack(pady=8, ipady=6, ipadx=8)

        self.create_button(
            self.main,
            "BACK TO CURRENT SCAN",
            ACCENT,
            ACCENT_HOVER,
            self.show_current_scan
        ).pack(pady=(0, 8), ipady=6, ipadx=8)

    # ========================================================
    # LOAD HISTORY
    # ========================================================

    def load_scan_history(self):

        if not os.path.exists(HISTORY_FILE):
            return []

        try:
            with open(
                HISTORY_FILE, "r", encoding="utf-8"
            ) as file:
                data = json.load(file)

            return data if isinstance(data, list) else []

        except (OSError, json.JSONDecodeError) as error:
            print("[GUI] History load error:", error)
            return []

    # ========================================================
    # SAVE HISTORY
    # ========================================================

    def save_scan_to_history(
        self,
        scan_name,
        target,
        results,
        report_path
    ):

        history = self.load_scan_history()

        history.append({
            "scan_name": scan_name,
            "target": target,
            "scan_time": self.current_scan_time,
            "profile": self.current_profile,
            "results": results,
            "report_path": report_path,
            "json_report_path": self.current_json_path,
        })

        try:
            with open(
                HISTORY_FILE, "w", encoding="utf-8"
            ) as file:
                json.dump(
                    history,
                    file,
                    indent=4,
                    ensure_ascii=False
                )

        except OSError as error:
            print("[GUI] History save error:", error)

    # ========================================================
    # PREVIOUS SCAN DASHBOARD
    # ========================================================

    def show_dashboard(self):

        if not self.require_permission("view_scan_history"):
            return

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text="Previous Scan Dashboard",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 10))

        history = self.load_scan_history()

        if not history:
            ctk.CTkLabel(
                self.main,
                text="No previous scan results found.",
                font=("Arial", 16),
                text_color=SECONDARY_TEXT
            ).pack(pady=60)

        else:
            frame = ctk.CTkScrollableFrame(
                self.main,
                fg_color=CARD_COLOR,
                corner_radius=15
            )
            frame.pack(fill="both", expand=True)

            for item in reversed(history):

                card = ctk.CTkFrame(
                    frame,
                    fg_color="#172033",
                    corner_radius=12
                )
                card.pack(fill="x", padx=10, pady=7)

                ctk.CTkLabel(
                    card,
                    text=(
                        f"{item.get('scan_name', 'Scan')} | "
                        f"{item.get('scan_time', '')}"
                    ),
                    font=("Arial", 15, "bold"),
                    text_color=TEXT_COLOR
                ).pack(anchor="w", padx=15, pady=(12, 4))

                ctk.CTkLabel(
                    card,
                    text=(
                        f"Target: {item.get('target', 'Unknown')}\n"
                        f"Profile: {item.get('profile', 'Legacy')}"
                    ),
                    font=("Arial", 11),
                    text_color=SECONDARY_TEXT,
                    justify="left"
                ).pack(anchor="w", padx=15, pady=(0, 8))

                summary = self.calculate_summary(
                    item.get("results", {})
                )

                ctk.CTkLabel(
                    card,
                    text=(
                        f"PASS: {summary['PASS']}  |  "
                        f"WARNING: {summary['WARNING']}  |  "
                        f"INFO: {summary['INFO']}  |  "
                        f"MISSING: {summary['MISSING']}"
                    ),
                    font=("Arial", 11),
                    text_color=TEXT_COLOR
                ).pack(anchor="w", padx=15, pady=(0, 8))

                self.create_button(
                    card,
                    "VIEW SAVED RESULT",
                    ACCENT,
                    ACCENT_HOVER,
                    lambda x=item: self.show_saved_scan(x)
                ).pack(
                    anchor="w", padx=15, pady=(0, 12),
                    ipady=5, ipadx=5
                )

        self.create_button(
            self.main,
            "BACK TO HOME",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.show_home
        ).pack(pady=10, ipady=6, ipadx=8)

    # ========================================================
    # VIEW SAVED SCAN
    # ========================================================

    def show_saved_scan(self, item):

        if not self.require_permission("view_scan_history"):
            return

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text=f"Saved Scan: {item.get('scan_name', 'Scan')}",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            self.main,
            text=(
                f"Target: {item.get('target', 'Unknown')}\n"
                f"Profile: {item.get('profile', 'Legacy')}\n"
                f"Scan Time: {item.get('scan_time', '')}"
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT,
            justify="left"
        ).pack(anchor="w", pady=(0, 12))

        frame = ctk.CTkScrollableFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=15
        )
        frame.pack(fill="both", expand=True)

        results = item.get("results", {})

        self.create_summary_card(
            frame,
            self.calculate_summary(results)
        )
        self.display_results(frame, results)

        report_path = item.get("report_path", "")

        if report_path:
            self.create_button(
                self.main,
                "DOWNLOAD REPORT",
                ORANGE,
                ORANGE_HOVER,
                lambda p=report_path: self.download_report(p)
            ).pack(pady=6, ipady=6, ipadx=8)

        self.create_button(
            self.main,
            "RECOMMENDATIONS",
            GREEN,
            GREEN_HOVER,
            lambda x=item: self.ask_recommendation_mode(
                x.get("results", {}),
                x.get("scan_name", "Saved Scan"),
                x.get("target", "Unknown"),
                x.get("scan_time", ""),
                back_command=lambda: self.show_saved_scan(x)
            )
        ).pack(pady=6, ipady=6, ipadx=8)

        self.create_button(
            self.main,
            "BACK TO DASHBOARD",
            ACCENT,
            ACCENT_HOVER,
            self.show_dashboard
        ).pack(pady=(0, 10), ipady=6, ipadx=8)


    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    def ask_recommendation_mode(
        self,
        scan_result,
        scan_name="Scan",
        target="Unknown",
        scan_time="",
        back_command=None
    ):
        """Ask whether the user wants Normal or AI-based recommendations."""

        if not self.require_permission("view_scan_history"):
            return

        if not isinstance(scan_result, dict) or not scan_result:
            messagebox.showwarning(
                "Recommendations",
                "No scan result is available for recommendations."
            )
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Recommendation Mode")
        dialog.geometry("460x250")
        dialog.resizable(False, False)
        dialog.configure(fg_color=BG_COLOR)
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text="Choose Recommendation Mode",
            font=("Arial", 20, "bold"),
            text_color=TEXT_COLOR
        ).pack(pady=(30, 8))

        ctk.CTkLabel(
            dialog,
            text=(
                f"{scan_name}\n"
                "Select how you want the findings to be analyzed."
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT,
            justify="center"
        ).pack(pady=(0, 22))

        button_frame = ctk.CTkFrame(
            dialog,
            fg_color="transparent"
        )
        button_frame.pack()

        def select_mode(mode):
            dialog.destroy()
            self.show_recommendations(
                scan_result,
                mode,
                scan_name,
                target,
                scan_time,
                back_command
            )

        self.create_button(
            button_frame,
            "NORMAL",
            ACCENT,
            ACCENT_HOVER,
            lambda: select_mode("normal"),
            width=14
        ).pack(side="left", padx=8, ipady=7)

        self.create_button(
            button_frame,
            "AI BASED",
            GREEN,
            GREEN_HOVER,
            lambda: select_mode("ai"),
            width=14
        ).pack(side="left", padx=8, ipady=7)

        ctk.CTkButton(
            dialog,
            text="CANCEL",
            fg_color=DARK_BUTTON,
            hover_color=DARK_BUTTON_HOVER,
            command=dialog.destroy,
            width=140
        ).pack(pady=18)

    def show_recommendations(
        self,
        scan_result,
        mode,
        scan_name,
        target,
        scan_time,
        back_command=None
    ):
        """Display recommendations for a selected scan result."""

        if not self.require_permission("view_scan_history"):
            return

        self.clear_main()

        mode_label = (
            "AI Based"
            if str(mode).lower() == "ai"
            else "Normal"
        )

        ctk.CTkLabel(
            self.main,
            text=f"{mode_label} Recommendations",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            self.main,
            text=(
                f"Scan: {scan_name}\n"
                f"Target: {target}\n"
                f"Scan Time: {scan_time}"
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT,
            justify="left"
        ).pack(anchor="w", pady=(0, 12))

        try:
            result = generate_recommendations(
                scan_result,
                mode
            )
        except Exception as error:
            result = {
                "success": False,
                "message": f"Recommendation engine error: {error}"
            }

        frame = ctk.CTkScrollableFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=15
        )
        frame.pack(fill="both", expand=True)

        if isinstance(result, dict):
            if result.get("success") is False:
                message = result.get(
                    "message",
                    "No recommendations available."
                )

                ctk.CTkLabel(
                    frame,
                    text=message,
                    font=("Arial", 14),
                    text_color=SECONDARY_TEXT,
                    wraplength=900,
                    justify="left"
                ).pack(
                    anchor="w",
                    padx=20,
                    pady=30
                )
            else:
                text = format_recommendations(result)

                ctk.CTkLabel(
                    frame,
                    text=text,
                    font=("Arial", 13),
                    text_color=TEXT_COLOR,
                    wraplength=900,
                    justify="left"
                ).pack(
                    anchor="w",
                    padx=20,
                    pady=20
                )

        elif isinstance(result, list):
            if not result:
                ctk.CTkLabel(
                    frame,
                    text="No recommendations available for this scan.",
                    font=("Arial", 14),
                    text_color=SECONDARY_TEXT
                ).pack(pady=40)
            else:
                for number, item in enumerate(result, start=1):
                    card = ctk.CTkFrame(
                        frame,
                        fg_color="#172033",
                        corner_radius=12
                    )
                    card.pack(
                        fill="x",
                        padx=10,
                        pady=7
                    )

                    ctk.CTkLabel(
                        card,
                        text=(
                            f"{number}. "
                            f"{item.get('finding', 'Unknown Finding')}"
                        ),
                        font=("Arial", 15, "bold"),
                        text_color=TEXT_COLOR,
                        wraplength=850,
                        justify="left"
                    ).pack(
                        anchor="w",
                        padx=15,
                        pady=(12, 5)
                    )

                    ctk.CTkLabel(
                        card,
                        text=(
                            f"Severity: {item.get('severity', 'Unknown')}\n"
                            f"Evidence: {item.get('evidence', 'N/A')}\n\n"
                            f"Recommendation:\n"
                            f"{item.get('recommendation', 'No recommendation available.')}"
                        ),
                        font=("Arial", 12),
                        text_color=SECONDARY_TEXT,
                        wraplength=850,
                        justify="left"
                    ).pack(
                        anchor="w",
                        padx=15,
                        pady=(0, 12)
                    )

        actions = ctk.CTkFrame(
            self.main,
            fg_color="transparent"
        )
        actions.pack(pady=10)

        self.create_button(
            actions,
            "CHANGE MODE",
            ACCENT,
            ACCENT_HOVER,
            lambda: self.ask_recommendation_mode(
                scan_result,
                scan_name,
                target,
                scan_time,
                back_command
            )
        ).pack(
            side="left",
            padx=5,
            ipady=6,
            ipadx=5
        )

        if back_command:
            self.create_button(
                actions,
                "BACK",
                DARK_BUTTON,
                DARK_BUTTON_HOVER,
                back_command
            ).pack(
                side="left",
                padx=5,
                ipady=6,
                ipadx=5
            )

        self.create_button(
            actions,
            "RECOMMENDATIONS HOME",
            GREEN,
            GREEN_HOVER,
            self.show_recommendations_history
        ).pack(
            side="left",
            padx=5,
            ipady=6,
            ipadx=5
        )

    def show_recommendations_history(self):
        """Show previous scans from which recommendations can be generated."""

        if not self.require_permission("view_scan_history"):
            return

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text="Recommendations",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            self.main,
            text=(
                "Select a previous scan result and then choose "
                "Normal or AI Based recommendations."
            ),
            font=("Arial", 12),
            text_color=SECONDARY_TEXT
        ).pack(anchor="w", pady=(0, 12))

        history = self.load_scan_history()

        if not history:
            ctk.CTkLabel(
                self.main,
                text="No previous scan results found.",
                font=("Arial", 16),
                text_color=SECONDARY_TEXT
            ).pack(pady=60)
        else:
            frame = ctk.CTkScrollableFrame(
                self.main,
                fg_color=CARD_COLOR,
                corner_radius=15
            )
            frame.pack(fill="both", expand=True)

            for item in reversed(history):
                card = ctk.CTkFrame(
                    frame,
                    fg_color="#172033",
                    corner_radius=12
                )
                card.pack(fill="x", padx=10, pady=7)

                ctk.CTkLabel(
                    card,
                    text=(
                        f"{item.get('scan_name', 'Scan')} | "
                        f"{item.get('scan_time', '')}"
                    ),
                    font=("Arial", 15, "bold"),
                    text_color=TEXT_COLOR
                ).pack(
                    anchor="w",
                    padx=15,
                    pady=(12, 4)
                )

                ctk.CTkLabel(
                    card,
                    text=(
                        f"Target: {item.get('target', 'Unknown')}\n"
                        f"Profile: {item.get('profile', 'Legacy')}"
                    ),
                    font=("Arial", 11),
                    text_color=SECONDARY_TEXT,
                    justify="left"
                ).pack(
                    anchor="w",
                    padx=15,
                    pady=(0, 8)
                )

                self.create_button(
                    card,
                    "SELECT RESULT",
                    GREEN,
                    GREEN_HOVER,
                    lambda x=item: self.ask_recommendation_mode(
                        x.get("results", {}),
                        x.get("scan_name", "Saved Scan"),
                        x.get("target", "Unknown"),
                        x.get("scan_time", ""),
                        back_command=self.show_recommendations_history
                    )
                ).pack(
                    anchor="w",
                    padx=15,
                    pady=(0, 12),
                    ipady=5,
                    ipadx=5
                )

        self.create_button(
            self.main,
            "BACK TO HOME",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.show_home
        ).pack(pady=10, ipady=6, ipadx=8)

    # ========================================================
    # SECURITY REPORTS
    # ========================================================

    def show_reports(self):

        if not self.require_permission("view_reports"):
            return

        self.clear_main()

        ctk.CTkLabel(
            self.main,
            text="Security Reports",
            font=("Arial", 24, "bold"),
            text_color=TEXT_COLOR
        ).pack(anchor="w", pady=(0, 10))

        history = self.load_scan_history()

        if not history:
            ctk.CTkLabel(
                self.main,
                text="No security reports found.",
                font=("Arial", 16),
                text_color=SECONDARY_TEXT
            ).pack(pady=60)

        else:
            frame = ctk.CTkScrollableFrame(
                self.main,
                fg_color=CARD_COLOR,
                corner_radius=15
            )
            frame.pack(fill="both", expand=True)

            for item in reversed(history):

                card = ctk.CTkFrame(
                    frame,
                    fg_color="#172033",
                    corner_radius=12
                )
                card.pack(fill="x", padx=10, pady=7)

                ctk.CTkLabel(
                    card,
                    text=item.get("scan_name", "Security Scan"),
                    font=("Arial", 15, "bold"),
                    text_color=TEXT_COLOR
                ).pack(anchor="w", padx=15, pady=(12, 4))

                ctk.CTkLabel(
                    card,
                    text=(
                        f"Target: {item.get('target', 'Unknown')}\n"
                        f"Profile: {item.get('profile', 'Legacy')}\n"
                        f"Date: {item.get('scan_time', '')}"
                    ),
                    font=("Arial", 11),
                    text_color=SECONDARY_TEXT,
                    justify="left"
                ).pack(anchor="w", padx=15, pady=(0, 8))

                report_path = item.get("report_path", "")

                if report_path:
                    self.create_button(
                        card,
                        "DOWNLOAD REPORT",
                        ORANGE,
                        ORANGE_HOVER,
                        lambda p=report_path: self.download_report(p)
                    ).pack(
                        anchor="w", padx=15, pady=(0, 12),
                        ipady=5, ipadx=5
                    )

        self.create_button(
            self.main,
            "BACK TO HOME",
            DARK_BUTTON,
            DARK_BUTTON_HOVER,
            self.show_home
        ).pack(pady=10, ipady=6, ipadx=8)

    # ========================================================
    # WRITE REPORT DATA
    # ========================================================

    def write_report_data(self, file, data, level=0):

        indent = "    " * level

        if isinstance(data, dict):

            for key, value in data.items():
                file.write(f"{indent}{key}:\n")
                self.write_report_data(file, value, level + 1)

        elif isinstance(data, list):

            if not data:
                file.write(f"{indent}(None)\n")

            for item in data:
                self.write_report_data(file, item, level + 1)

        else:
            file.write(f"{indent}{data}\n")

    # ========================================================
    # CREATE SECURITY REPORT
    # ========================================================

    def create_security_report(
        self,
        scan_name,
        target,
        results
    ):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        safe_name = "".join(
            char if char.isalnum() or char in "_-" else "_"
            for char in scan_name.replace(" ", "_")
        )

        filename = f"{safe_name}_{timestamp}.txt"

        report_path = os.path.join(
            REPORTS_FOLDER, filename
        )
        self.current_json_path = ""

        summary = self.calculate_summary(results)

        try:
            with open(
                report_path, "w", encoding="utf-8"
            ) as file:

                file.write("WEB APPLICATION SECURITY TOOLKIT\n")
                file.write("=" * 60 + "\n\n")
                file.write(f"Scan Type    : {scan_name}\n")
                file.write(f"Scan Profile : {self.current_profile}\n")
                file.write(f"Target       : {target}\n")
                file.write(f"Scan Time    : {self.current_scan_time}\n\n")

                file.write("SECURITY SUMMARY\n")
                file.write("-" * 60 + "\n")
                for key, value in summary.items():
                    file.write(f"{key:<10}: {value}\n")

                file.write("\nDETAILED RESULTS\n")
                file.write("-" * 60 + "\n\n")

                self.write_report_data(file, results)

                file.write("\n" + "=" * 60 + "\n")
                file.write("End of Security Report\n")

        except OSError as error:
            print("[GUI] Report creation error:", error)
            return ""

        json_path = os.path.splitext(report_path)[0] + ".json"
        try:
            with open(json_path, "w", encoding="utf-8") as file:
                json.dump(
                    {
                        "schema_version": "1.0",
                        "tool": "Web Application Security Toolkit",
                        "scan_type": scan_name,
                        "scan_profile": self.current_profile,
                        "target": target,
                        "scan_time": self.current_scan_time,
                        "summary": summary,
                        "results": results,
                    },
                    file,
                    indent=2,
                    ensure_ascii=False,
                )
            self.current_json_path = json_path
        except (OSError, TypeError, ValueError) as error:
            print("[GUI] Structured report creation error:", error)

        return report_path

    def export_current_scan_json(self):
        if not self.require_permission("generate_reports"):
            return
        if not self.current_results:
            messagebox.showwarning(
                "No Scan Data",
                "Run a scan before exporting structured results."
            )
            return

        default_name = os.path.basename(self.current_json_path) or "security_scan.json"
        save_path = filedialog.asksaveasfilename(
            title="Export Scan Results as JSON",
            initialfile=default_name,
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("All Files", "*.*")],
        )
        if not save_path:
            return

        try:
            payload = {
                "schema_version": "1.0",
                "tool": "Web Application Security Toolkit",
                "scan_type": self.current_scan_name,
                "scan_profile": self.current_profile,
                "target": self.current_target,
                "scan_time": self.current_scan_time,
                "summary": self.calculate_summary(self.current_results),
                "results": self.current_results,
            }
            with open(save_path, "w", encoding="utf-8") as file:
                json.dump(payload, file, indent=2, ensure_ascii=False)
            messagebox.showinfo(
                "Export Complete",
                f"Structured scan results saved to:\n\n{save_path}"
            )
        except (OSError, TypeError, ValueError) as error:
            messagebox.showerror(
                "Export Failed",
                f"Could not export scan results:\n\n{error}"
            )

    # ========================================================
    # DOWNLOAD SECURITY REPORT
    # ========================================================

    def download_report(self, report_path):

        if not self.require_permission("view_reports"):
            return

        if not report_path:
            messagebox.showwarning(
                "Report Not Available",
                "No report is available."
            )
            return

        if not os.path.exists(report_path):
            messagebox.showerror(
                "Report Missing",
                "The report file could not be found."
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Download Security Report",
            initialfile=os.path.basename(report_path),
            defaultextension=".txt",
            filetypes=[
                ("Text Report", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if not save_path:
            return

        try:
            with open(
                report_path, "r", encoding="utf-8"
            ) as source:
                content = source.read()

            with open(
                save_path, "w", encoding="utf-8"
            ) as destination:
                destination.write(content)

            messagebox.showinfo(
                "Download Complete",
                f"Security report saved to:\n\n{save_path}"
            )

        except OSError as error:
            messagebox.showerror("Download Error", str(error))

    # ========================================================
    # DOWNLOAD CURRENT DASHBOARD
    # ========================================================

    def download_current_dashboard(self):

        if not self.require_permission("generate_reports"):
            return

        if not self.current_results:
            messagebox.showwarning(
                "No Dashboard",
                "No current scan results are available."
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Download Current Dashboard",
            initialfile="Current_Security_Dashboard.txt",
            defaultextension=".txt",
            filetypes=[
                ("Text Dashboard", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if not save_path:
            return

        try:
            summary = self.calculate_summary(
                self.current_results
            )

            with open(
                save_path, "w", encoding="utf-8"
            ) as file:

                file.write("WEB APPLICATION SECURITY TOOLKIT\n")
                file.write("CURRENT SECURITY DASHBOARD\n")
                file.write("=" * 60 + "\n\n")

                file.write(f"Target       : {self.current_target}\n")
                file.write(f"Scan Type    : {self.current_scan_name}\n")
                file.write(f"Scan Profile : {self.current_profile}\n")
                file.write(f"Scan Time    : {self.current_scan_time}\n\n")

                file.write("SECURITY SUMMARY\n")
                file.write("-" * 60 + "\n")

                for key, value in summary.items():
                    file.write(f"{key:<10}: {value}\n")

                file.write("\nDETAILED RESULTS\n")
                file.write("-" * 60 + "\n\n")

                self.write_report_data(
                    file, self.current_results
                )

            messagebox.showinfo(
                "Dashboard Downloaded",
                f"Dashboard saved to:\n\n{save_path}"
            )

        except OSError as error:
            messagebox.showerror("Download Error", str(error))

    # ========================================================
    # SCAN ERROR
    # ========================================================

    def scan_error(self, error):

        self.scanning = False

        self.audit.log(
            self.current_user.username,
            "SCAN_FAILED",
            f"{self.current_scan_name}; {error}"
        )

        print("[GUI ERROR]", error)

        messagebox.showerror(
            "Scan Error",
            f"An error occurred:\n\n{error}"
        )

        self.show_home()


# Launch through the login screen when this file is run directly.
if __name__ == "__main__":
    from gui.login import LoginApp

    app = LoginApp()
    app.mainloop()


