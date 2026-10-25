
import os
import json
import time
import hmac
import hashlib
import secrets
from datetime import datetime, timezone
from getpass import getpass


# ============================================================
# PROJECT PATHS AND SETTINGS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "security_data")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
AUTH_STATE_FILE = os.path.join(DATA_DIR, "auth_state.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")

ADMIN_USERNAME = "diya"

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 300
SESSION_TIMEOUT = 600

PBKDF2_ITERATIONS = 600_000
HASH_NAME = "sha256"

os.makedirs(DATA_DIR, exist_ok=True)


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path, default):
    if not os.path.exists(path):
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path, data):
    temporary_path = path + ".tmp"

    with open(temporary_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    os.replace(temporary_path, path)


def current_time():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# PASSWORD SECURITY
# ============================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    salt_bytes = bytes.fromhex(salt)

    password_hash = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS
    ).hex()

    return salt, password_hash


def verify_password(password, salt, expected_hash):
    try:
        _, actual_hash = hash_password(password, salt)
        return hmac.compare_digest(actual_hash, expected_hash)
    except (ValueError, TypeError):
        return False


# ============================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================

ROLE_PERMISSIONS = {
    "admin": {
        "recon",
        "security_config",
        "vulnerability_assessment",
        "run_scan",
        "view_reports",
        "generate_reports",
        "view_scan_history",
        "manage_users",
        "change_own_password",
        "view_audit_log",
        "check_audit_integrity",
        "run_rbac_test",
    },

    "security_analyst": {
        "recon",
        "security_config",
        "vulnerability_assessment",
        "run_scan",
        "view_reports",
        "generate_reports",
        "view_scan_history",
        "change_own_password",
    },

    "scanner": {
        "recon",
        "run_scan",
        "view_reports",
        "view_scan_history",
        "change_own_password",
    },

    "viewer": {
        "view_reports",
        "view_scan_history",
        "change_own_password",
    },
}


# ============================================================
# USER MODEL
# ============================================================

class User:
    def __init__(
        self,
        username,
        salt,
        password_hash,
        roles=None,
        active=True
    ):
        self.username = username
        self.salt = salt
        self.password_hash = password_hash
        self.roles = roles or ["viewer"]
        self.active = active

    def has_permission(self, permission):
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True
        return False

    def to_dict(self):
        return {
            "username": self.username,
            "roles": self.roles,
            "password_data": {
                "salt": self.salt,
                "password_hash": self.password_hash,
            },
            "active": self.active,
        }


# ============================================================
# AUDIT LOGGER WITH HASH CHAIN
# ============================================================

class AuditLogger:
    def __init__(self, path=AUDIT_FILE):
        self.path = path

    def _read_events(self):
        events = []

        if not os.path.exists(self.path):
            return events

        with open(self.path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    raise ValueError(
                        f"Invalid audit log JSON at line {line_number}."
                    )

        return events

    @staticmethod
    def _event_hash(event):
        payload = {
            "timestamp": event["timestamp"],
            "username": event["username"],
            "action": event["action"],
            "details": event["details"],
            "previous_hash": event["previous_hash"],
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def log(self, username, action, details=""):
        events = self._read_events()
        previous_hash = (
            events[-1].get("event_hash", "GENESIS")
            if events
            else "GENESIS"
        )

        event = {
            "timestamp": current_time(),
            "username": username or "anonymous",
            "action": action,
            "details": str(details),
            "previous_hash": previous_hash,
        }

        event["event_hash"] = self._event_hash(event)

        with open(self.path, "a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

    def verify_integrity(self):
        events = self._read_events()
        expected_previous_hash = "GENESIS"

        for index, event in enumerate(events, start=1):
            if event.get("previous_hash") != expected_previous_hash:
                return False, f"Hash chain mismatch at event {index}."

            expected_hash = self._event_hash(event)

            if not hmac.compare_digest(
                str(event.get("event_hash", "")),
                expected_hash
            ):
                return False, f"Event hash mismatch at event {index}."

            expected_previous_hash = expected_hash

        return True, f"Verified {len(events)} audit events."

    def show_events(self):
        events = self._read_events()

        if not events:
            print("\nNo audit events recorded.")
            return

        print("\n========== AUDIT LOG ==========")

        for event in events:
            print(
                f"\nTime: {event.get('timestamp')}"
                f"\nUser: {event.get('username')}"
                f"\nAction: {event.get('action')}"
                f"\nDetails: {event.get('details')}"
            )

        print("\n===============================")


# ============================================================
# USER MANAGER
# ============================================================

class UserManager:
    def __init__(self, audit_logger):
        self.users = {}
        self.audit = audit_logger
        self.load_users()

    def load_users(self):
        raw_users = load_json(USERS_FILE, [])

        # Your existing file uses a JSON list.
        # Older versions may use a dictionary.
        if isinstance(raw_users, list):
            records = raw_users

        elif isinstance(raw_users, dict):
            records = []

            for key, value in raw_users.items():
                if not isinstance(value, dict):
                    raise ValueError(
                        f"Invalid user record for {key}."
                    )

                record = dict(value)
                record.setdefault("username", key)
                records.append(record)

        else:
            raise ValueError(
                "users.json must contain a JSON list or object."
            )

        loaded_users = {}

        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid user record in users.json.")

            username = str(record.get("username", "")).strip()

            if not username:
                raise ValueError(
                    "A user record is missing its username."
                )

            # Support both nested and older password formats.
            password_data = record.get("password_data", {})

            if not isinstance(password_data, dict):
                password_data = {}

            salt = record.get("salt") or password_data.get("salt")
            password_hash = (
                record.get("password_hash")
                or password_data.get("password_hash")
            )

            if not salt or not password_hash:
                raise ValueError(
                    f"Password data is missing for {username}."
                )

            # Support both one role and multiple roles.
            roles = record.get("roles")

            if not roles:
                role = record.get("role", "viewer")
                roles = [role] if isinstance(role, str) else role

            if isinstance(roles, str):
                roles = [roles]

            if not isinstance(roles, list) or not roles:
                raise ValueError(
                    f"Invalid roles for user {username}."
                )

            valid_roles = set(ROLE_PERMISSIONS)

            if any(
                not isinstance(role, str) or role not in valid_roles
                for role in roles
            ):
                raise ValueError(
                    f"Unknown role in user record: {username}."
                )

            normalized_username = username.casefold()

            if normalized_username in loaded_users:
                raise ValueError(
                    "Duplicate usernames ignoring letter case."
                )

            loaded_users[normalized_username] = User(
                username=username,
                salt=salt,
                password_hash=password_hash,
                roles=roles,
                active=record.get("active", True),
            )

        self.users = loaded_users

    def save_users(self):
        # Keep the existing list-based JSON structure.
        records = [
            user.to_dict()
            for user in self.users.values()
        ]

        save_json(USERS_FILE, records)

    def get_user(self, username):
        return self.users.get(username.strip().casefold())

    def list_users(self):
        print("\n========== USERS ==========")

        for user in self.users.values():
            status = "Active" if user.active else "Disabled"

            print(
                f"Username: {user.username} | "
                f"Roles: {', '.join(user.roles)} | "
                f"Status: {status}"
            )

        print("===========================")

    def create_user(self, actor, username, password, roles):
        username = username.strip()

        if not username:
            print("Username cannot be empty.")
            return False

        if self.get_user(username):
            print("A user with this username already exists.")
            return False

        if len(password) < 8:
            print("Password must contain at least 8 characters.")
            return False

        if not roles or any(
            role not in ROLE_PERMISSIONS for role in roles
        ):
            print("Invalid role selection.")
            return False

        salt, password_hash = hash_password(password)

        user = User(
            username=username,
            salt=salt,
            password_hash=password_hash,
            roles=roles,
            active=True,
        )

        self.users[username.casefold()] = user
        self.save_users()

        self.audit.log(
            actor.username,
            "CREATE_USER",
            f"Created user {username} with roles {roles}"
        )

        print(f"User '{username}' created successfully.")
        return True

    def remove_user(self, actor, username):
        user = self.get_user(username)

        if not user:
            print("User not found.")
            return False

        if user.username.casefold() == ADMIN_USERNAME.casefold():
            print("The primary admin account cannot be removed here.")
            return False

        del self.users[user.username.casefold()]
        self.save_users()

        self.audit.log(
            actor.username,
            "REMOVE_USER",
            f"Removed user {user.username}"
        )

        print("User removed successfully.")
        return True

    def change_roles(self, actor, username, roles):
        user = self.get_user(username)

        if not user:
            print("User not found.")
            return False

        if not roles or any(
            role not in ROLE_PERMISSIONS for role in roles
        ):
            print("Invalid role selection.")
            return False

        # Prevent accidental removal of the primary admin role.
        if user.username.casefold() == ADMIN_USERNAME.casefold():
            if "admin" not in roles:
                print("The primary admin must retain the admin role.")
                return False

        user.roles = list(dict.fromkeys(roles))
        self.save_users()

        self.audit.log(
            actor.username,
            "CHANGE_ROLES",
            f"Changed roles for {user.username}: {user.roles}"
        )

        print("Roles updated successfully.")
        return True

    def change_password(self, user, old_password, new_password):
        if not verify_password(
            old_password, user.salt, user.password_hash
        ):
            print("Current password is incorrect.")
            return False

        if len(new_password) < 8:
            print("New password must contain at least 8 characters.")
            return False

        salt, password_hash = hash_password(new_password)

        user.salt = salt
        user.password_hash = password_hash

        self.save_users()

        self.audit.log(
            user.username,
            "CHANGE_PASSWORD",
            "User changed their own password"
        )

        print("Password changed successfully.")
        return True


# ============================================================
# AUTHENTICATION AND PERSISTENT LOCKOUT
# ============================================================

class Authenticator:
    def __init__(self, user_manager, audit_logger):
        self.user_manager = user_manager
        self.audit = audit_logger
        self.state = load_json(AUTH_STATE_FILE, {})

        if not isinstance(self.state, dict):
            self.state = {}

    def _save_state(self):
        save_json(AUTH_STATE_FILE, self.state)

    def login(self, username, password):
        user = self.user_manager.get_user(username)

        if user is None:
            self.audit.log(
                username,
                "LOGIN_FAILED",
                "Unknown username"
            )
            print("Invalid username or password.")
            return None

        key = user.username.casefold()

        if not user.active:
            self.audit.log(
                user.username,
                "LOGIN_BLOCKED",
                "Account disabled"
            )
            print("This account is disabled.")
            return None

        entry = self.state.get(key, {})

        if not isinstance(entry, dict):
            entry = {}

        lock_until = float(entry.get("lock_until", 0))

        if time.time() < lock_until:
            remaining = int(lock_until - time.time()) + 1
            print(
                f"Account temporarily locked. "
                f"Try again in {remaining} seconds."
            )
            return None

        if lock_until:
            entry = {"failures": 0, "lock_until": 0}

        if verify_password(password, user.salt, user.password_hash):
            self.state[key] = {
                "failures": 0,
                "lock_until": 0,
            }
            self._save_state()

            self.audit.log(
                user.username,
                "LOGIN_SUCCESS",
                "Successful login"
            )

            print(f"\nWelcome, {user.username}!")
            return user

        failures = int(entry.get("failures", 0)) + 1

        if failures >= MAX_LOGIN_ATTEMPTS:
            entry = {
                "failures": 0,
                "lock_until": time.time() + LOCKOUT_SECONDS,
            }

            self.audit.log(
                user.username,
                "ACCOUNT_LOCKED",
                f"Too many failed attempts; lockout {LOCKOUT_SECONDS}s"
            )

            print(
                f"Too many failed attempts. "
                f"Account locked for {LOCKOUT_SECONDS // 60} minutes."
            )
        else:
            entry = {
                "failures": failures,
                "lock_until": 0,
            }

            print(
                f"Invalid username or password. "
                f"Attempts remaining: "
                f"{MAX_LOGIN_ATTEMPTS - failures}"
            )

        self.state[key] = entry
        self._save_state()

        self.audit.log(
            user.username,
            "LOGIN_FAILED",
            f"Failed attempt {failures}"
        )

        return None


# ============================================================
# REFERENCE MONITOR
# ============================================================

class ReferenceMonitor:
    def __init__(self, audit_logger):
        self.audit = audit_logger

    def authorize(self, user, permission):
        allowed = user.has_permission(permission)

        self.audit.log(
            user.username,
            "ACCESS_CHECK",
            f"Permission={permission}; allowed={allowed}"
        )

        if not allowed:
            print(
                f"Access denied: role(s) {user.roles} "
                f"cannot perform '{permission}'."
            )

        return allowed

    def execute(self, user, permission, action):
        if not self.authorize(user, permission):
            return False

        action()
        return True


# ============================================================
# SECURITY CORE
# ============================================================

class SecurityCore:
    def __init__(self):
        self.audit = AuditLogger()
        self.user_manager = UserManager(self.audit)
        self.authenticator = Authenticator(
            self.user_manager,
            self.audit
        )
        self.reference_monitor = ReferenceMonitor(self.audit)

        self.current_user = None
        self.last_activity = 0

    def check_session(self):
        if self.current_user is None:
            return False

        if time.time() - self.last_activity > SESSION_TIMEOUT:
            self.audit.log(
                self.current_user.username,
                "SESSION_TIMEOUT",
                "Session expired due to inactivity"
            )

            print("\nSession expired due to inactivity.")
            self.current_user = None
            return False

        self.last_activity = time.time()
        return True

    def require_permission(self, permission):
        if not self.check_session():
            print("Please log in again.")
            return False

        return self.reference_monitor.authorize(
            self.current_user,
            permission
        )

    def login_menu(self):
        username = input("Username: ").strip()
        password = getpass("Password: ")

        user = self.authenticator.login(username, password)

        if user:
            self.current_user = user
            self.last_activity = time.time()

    def manage_users_menu(self):
        if not self.require_permission("manage_users"):
            return

        while True:
            print("\n========== MANAGE USERS ==========")
            print("1. View users")
            print("2. Create user")
            print("3. Remove user")
            print("4. Change user roles")
            print("0. Back")

            choice = input("Select: ").strip()

            if choice == "1":
                self.user_manager.list_users()

            elif choice == "2":
                username = input("New username: ").strip()
                password = getpass("New password: ")

                print(
                    "Roles: admin, security_analyst, "
                    "scanner, viewer"
                )
                roles = input(
                    "Enter role(s), comma-separated: "
                ).strip().lower()

                selected_roles = list(dict.fromkeys(
                    role.strip()
                    for role in roles.split(",")
                    if role.strip()
                ))

                self.user_manager.create_user(
                    self.current_user,
                    username,
                    password,
                    selected_roles
                )

            elif choice == "3":
                username = input("Username to remove: ").strip()

                self.user_manager.remove_user(
                    self.current_user,
                    username
                )

            elif choice == "4":
                username = input("Username: ").strip()

                print(
                    "Roles: admin, security_analyst, "
                    "scanner, viewer"
                )
                roles = input(
                    "Enter new role(s), comma-separated: "
                ).strip().lower()

                selected_roles = list(dict.fromkeys(
                    role.strip()
                    for role in roles.split(",")
                    if role.strip()
                ))

                self.user_manager.change_roles(
                    self.current_user,
                    username,
                    selected_roles
                )

            elif choice == "0":
                break

            else:
                print("Invalid choice.")

    def change_own_password(self):
        if not self.require_permission("change_own_password"):
            return

        old_password = getpass("Current password: ")
        new_password = getpass("New password: ")
        confirm_password = getpass("Confirm new password: ")

        if new_password != confirm_password:
            print("Passwords do not match.")
            return

        self.user_manager.change_password(
            self.current_user,
            old_password,
            new_password
        )

    def audit_menu(self):
        if not self.require_permission("view_audit_log"):
            return

        self.audit.show_events()

        choice = input(
            "\nCheck audit integrity? (y/n): "
        ).strip().lower()

        if choice == "y":
            if not self.require_permission("check_audit_integrity"):
                return

            try:
                valid, message = self.audit.verify_integrity()
                print(
                    f"\nIntegrity: {'VALID' if valid else 'FAILED'}"
                )
                print(message)
            except (OSError, ValueError) as error:
                print(f"Could not verify audit log: {error}")

    def rbac_self_test(self):
        if not self.require_permission("run_rbac_test"):
            return

        print("\n========== RBAC SELF-TEST ==========")

        for role, permissions in ROLE_PERMISSIONS.items():
            test_user = User(
                username=f"test_{role}",
                salt="00",
                password_hash="",
                roles=[role]
            )

            print(f"\nRole: {role}")

            for permission in sorted(permissions):
                print(f"  ALLOW  {permission}")

            for permission in sorted(
                {"manage_users", "run_scan", "view_reports"} - permissions
            ):
                print(f"  DENY   {permission}")

            # Basic self-test: all assigned permissions must be allowed.
            assert all(
                test_user.has_permission(permission)
                for permission in permissions
            )

        print("\nRBAC self-test passed.")

        self.audit.log(
            self.current_user.username,
            "RBAC_SELF_TEST",
            "Basic role-permission checks passed"
        )

    def placeholder_action(self, name):
        print(
            f"\n'{name}' is an integration placeholder. "
            "Connect the relevant toolkit module to enable it."
        )

        self.audit.log(
            self.current_user.username,
            "PLACEHOLDER_ACTION",
            name
        )

    def main_menu(self):
        while True:
            print("\n========== SECURITY CORE ==========")

            if self.current_user:
                print(
                    f"Logged in: {self.current_user.username} "
                    f"| Roles: {', '.join(self.current_user.roles)}"
                )

            print("1. Login")
            print("2. Reconnaissance")
            print("3. Security configuration check")
            print("4. Vulnerability assessment")
            print("5. Run scan")
            print("6. View reports")
            print("7. Generate report")
            print("8. View scan history")
            print("9. Manage users")
            print("10. Change own password")
            print("11. View audit log / verify integrity")
            print("12. RBAC self-test")
            print("0. Exit")

            choice = input("Select: ").strip()

            if choice == "0":
                if self.current_user:
                    self.audit.log(
                        self.current_user.username,
                        "LOGOUT",
                        "User logged out"
                    )

                self.current_user = None
                print("Exiting Security Core.")
                break

            elif choice == "1":
                if self.current_user:
                    print("Please log out before switching accounts.")
                else:
                    self.login_menu()

            elif choice == "2":
                self.reference_monitor.execute(
                    self.current_user,
                    "recon",
                    lambda: self.placeholder_action("Reconnaissance")
                ) if self.current_user else print("Please log in first.")

            elif choice == "3":
                self.reference_monitor.execute(
                    self.current_user,
                    "security_config",
                    lambda: self.placeholder_action(
                        "Security configuration check"
                    )
                ) if self.current_user else print("Please log in first.")

            elif choice == "4":
                self.reference_monitor.execute(
                    self.current_user,
                    "vulnerability_assessment",
                    lambda: self.placeholder_action(
                        "Vulnerability assessment"
                    )
                ) if self.current_user else print("Please log in first.")

            elif choice == "5":
                self.reference_monitor.execute(
                    self.current_user,
                    "run_scan",
                    lambda: self.placeholder_action("Run scan")
                ) if self.current_user else print("Please log in first.")

            elif choice == "6":
                self.reference_monitor.execute(
                    self.current_user,
                    "view_reports",
                    lambda: self.placeholder_action("View reports")
                ) if self.current_user else print("Please log in first.")

            elif choice == "7":
                self.reference_monitor.execute(
                    self.current_user,
                    "generate_reports",
                    lambda: self.placeholder_action("Generate report")
                ) if self.current_user else print("Please log in first.")

            elif choice == "8":
                self.reference_monitor.execute(
                    self.current_user,
                    "view_scan_history",
                    lambda: self.placeholder_action("View scan history")
                ) if self.current_user else print("Please log in first.")

            elif choice == "9":
                if self.current_user:
                    self.manage_users_menu()
                else:
                    print("Please log in first.")

            elif choice == "10":
                if self.current_user:
                    self.change_own_password()
                else:
                    print("Please log in first.")

            elif choice == "11":
                if self.current_user:
                    self.audit_menu()
                else:
                    print("Please log in first.")

            elif choice == "12":
                if self.current_user:
                    self.rbac_self_test()
                else:
                    print("Please log in first.")

            else:
                print("Invalid choice. Try again.")


# ============================================================
# STARTUP
# ============================================================

def main():
    print("Starting Security Core...")

    try:
        core = SecurityCore()

        if core.user_manager.get_user(ADMIN_USERNAME) is None:
            print(
                f"\nWARNING: Admin account '{ADMIN_USERNAME}' "
                "was not found."
            )
            print(
                "No replacement admin has been created automatically. "
                "Check users.json before proceeding."
            )

        core.main_menu()

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("\nSecurity Core could not start.")
        print(f"Reason: {error}")

    except KeyboardInterrupt:
        print("\nProgram interrupted.")


if __name__ == "__main__":
    main()
