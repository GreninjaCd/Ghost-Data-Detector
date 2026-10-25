import hashlib
from typing import Dict, Set, Optional, Any
from code.loaders import load_user_identities, load_user_audit_log


def compute_email_hash(email: str) -> str:
    """Computes UTF-8 SHA-256 email hash matching Northstar Shop identity platform."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


class UserProfile:
    def __init__(self, user_id: str, name: str = "", email: str = "", phone: str = "", email_hash: str = ""):
        self.user_id: str = user_id
        self.canonical_name: str = name
        self.names: Set[str] = {name} if name else set()
        self.emails: Set[str] = {email.strip().lower()} if email else set()
        self.phones: Set[str] = {phone.strip()} if phone else set()
        self.hashes: Set[str] = {email_hash.strip().lower()} if email_hash else set()
        if email:
            self.hashes.add(compute_email_hash(email))

    def add_name(self, name: str):
        if name and name.strip():
            self.names.add(name.strip())

    def add_email(self, email: str):
        if email and email.strip():
            clean_email = email.strip().lower()
            self.emails.add(clean_email)
            self.hashes.add(compute_email_hash(clean_email))

    def add_phone(self, phone: str):
        if phone and phone.strip():
            self.phones.add(phone.strip())

    def add_hash(self, email_hash: str):
        if email_hash and email_hash.strip():
            self.hashes.add(email_hash.strip().lower())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "canonical_name": self.canonical_name,
            "names": sorted(list(self.names)),
            "emails": sorted(list(self.emails)),
            "phones": sorted(list(self.phones)),
            "hashes": sorted(list(self.hashes)),
        }


class IdentityGraph:
    def __init__(self):
        self.profiles: Dict[str, UserProfile] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self._build_graph()

    def _build_graph(self):
        # 1. Ingest current identities
        identities = load_user_identities()
        for row in identities:
            uid = row["user_id"]
            name = row.get("name", "")
            email = row.get("email", "")
            phone = row.get("phone", "")
            e_hash = row.get("email_hash", "")

            profile = UserProfile(uid, name=name, email=email, phone=phone, email_hash=e_hash)
            self.profiles[uid] = profile

            if email:
                self.email_to_uid[email.strip().lower()] = uid
            if phone:
                self.phone_to_uid[phone.strip()] = uid
            if e_hash:
                self.hash_to_uid[e_hash.strip().lower()] = uid
            if email:
                self.hash_to_uid[compute_email_hash(email)] = uid

        # 2. Ingest historical identity changes from audit log
        audit_rows = load_user_audit_log()
        for row in audit_rows:
            uid = row["user_id"]
            if uid not in self.profiles:
                self.profiles[uid] = UserProfile(uid)
            profile = self.profiles[uid]

            field = row.get("field_name")
            old_val = row.get("old_value", "").strip()
            new_val = row.get("new_value", "").strip()

            if field == "email":
                if old_val:
                    profile.add_email(old_val)
                    self.email_to_uid[old_val.lower()] = uid
                    self.hash_to_uid[compute_email_hash(old_val)] = uid
                if new_val:
                    profile.add_email(new_val)
                    self.email_to_uid[new_val.lower()] = uid
                    self.hash_to_uid[compute_email_hash(new_val)] = uid
            elif field == "phone":
                if old_val:
                    profile.add_phone(old_val)
                    self.phone_to_uid[old_val] = uid
                if new_val:
                    profile.add_phone(new_val)
                    self.phone_to_uid[new_val] = uid
            elif field == "email_hash":
                if old_val:
                    profile.add_hash(old_val)
                    self.hash_to_uid[old_val.lower()] = uid
                if new_val:
                    profile.add_hash(new_val)
                    self.hash_to_uid[new_val.lower()] = uid

    def get_profile_by_user_id(self, user_id: str) -> Optional[UserProfile]:
        return self.profiles.get(user_id)

    def resolve_email(self, email: str) -> Optional[UserProfile]:
        clean = email.strip().lower()
        uid = self.email_to_uid.get(clean)
        if uid:
            return self.profiles.get(uid)
        return None

    def resolve_phone(self, phone: str) -> Optional[UserProfile]:
        clean = phone.strip()
        uid = self.phone_to_uid.get(clean)
        if uid:
            return self.profiles.get(uid)
        return None

    def resolve_hash(self, email_hash: str) -> Optional[UserProfile]:
        clean = email_hash.strip().lower()
        uid = self.hash_to_uid.get(clean)
        if uid:
            return self.profiles.get(uid)
        return None

    def matches_user(self, user_id: str, text: str) -> bool:
        """Checks if text contains user_id or any of the user's direct identifiers."""
        profile = self.profiles.get(user_id)
        if not profile:
            return False
        if user_id in text:
            return True
        for email in profile.emails:
            if email in text.lower():
                return True
        for phone in profile.phones:
            if phone in text:
                return True
        for h in profile.hashes:
            if h in text.lower():
                return True
        return False
