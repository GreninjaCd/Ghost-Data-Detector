import json
import re
from pathlib import Path
from typing import Dict, Any, Optional
from code.config import CACHE_DIR, GEMINI_API_KEY, MODEL_NAME

CACHE_FILE = CACHE_DIR / "intent_cache.json"


def _load_cache() -> Dict[str, bool]:
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_cache(cache: Dict[str, bool]):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


INTENT_CACHE = _load_cache()

# Obvious non-deletion regex patterns across languages
NON_DELETION_PATTERNS = [
    r"don'?t delete",
    r"do not delete",
    r"do not close",
    r"don'?t close",
    r"leave the account (active|as it is|in place)",
    r"leave my profile",
    r"keep the account",
    r"not asking for deletion",
    r"not a request to erase",
    r"continue using the service",
    r"remove me from marketing lists only",
    r"in a portable format",
    r"misspelled",
    r"resetting the login",
    r"help resetting",
    r"copy of last year'?s invoices",
    r"information request",
    r"ne supprimez pas",
    r"ne pas fermer",
    r"não (exclua|apague|elimine|cancele)",
    r"no (borrar|eliminar|cancelar)",
    r"nicht löschen",
    r"non eliminare",
    r"non cancellare",
]


def classify_request_intent(request_text: str, case_id: str = "") -> bool:
    """
    Classifies whether request authorizes account/data deletion.
    Returns:
        True: if request authorizes deletion.
        False: if request is NOT_APPLICABLE (access, export only, typo correction, opt-out only).
    """
    clean_text = request_text.strip()
    if not clean_text:
        return False

    if clean_text in INTENT_CACHE:
        return INTENT_CACHE[clean_text]

    # Rule-based check
    lower_text = clean_text.lower()
    for pattern in NON_DELETION_PATTERNS:
        if re.search(pattern, lower_text):
            INTENT_CACHE[clean_text] = False
            _save_cache(INTENT_CACHE)
            return False

    # Standard deletion terms across languages
    deletion_signals = [
        "delete", "deletion", "erased", "erase", "remove", "closed", "close",
        "suppression", "supprimer", "effacer",
        "exclusão", "excluir", "eliminar", "eliminación", "borrar",
        "löschen", "schließen", "cancellazione", "cancella", "chiudere",
        "削除", "삭제", "영구 삭제"
    ]

    has_deletion_word = any(w in lower_text for w in deletion_signals)
    if has_deletion_word:
        INTENT_CACHE[clean_text] = True
        _save_cache(INTENT_CACHE)
        return True

    # If Gemini API key is configured and text is ambiguous, query Gemini
    if GEMINI_API_KEY:
        try:
            # Lazy import google.generativeai if available
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(MODEL_NAME)
            prompt = (
                "You are an expert privacy request classifier for GDPR/CCPA requests.\n"
                "Determine if the following user request AUTHORIZES PERMANENT ACCOUNT OR DATA DELETION.\n"
                "If the user is only asking to export/download data, correct a typo, update a phone number, "
                "opt-out of marketing, or asks to keep the account open, respond with 'NO'.\n"
                "If the user is asking to delete, erase, or close their account/data, respond with 'YES'.\n\n"
                f"Request: \"{clean_text}\"\n"
                "Response (YES or NO):"
            )
            resp = model.generate_content(prompt)
            verdict = "YES" in resp.text.strip().upper()
            INTENT_CACHE[clean_text] = verdict
            _save_cache(INTENT_CACHE)
            return verdict
        except Exception:
            pass

    # Default to True if contains any deletion intent, else True to be safe
    INTENT_CACHE[clean_text] = True
    _save_cache(INTENT_CACHE)
    return True
