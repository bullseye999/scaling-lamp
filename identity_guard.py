#!/usr/bin/env python3
# identity_guard.py - Ciph switches personality based on who is talking
# Authentication: passphrase + personal challenge question

import hashlib
import json
import secrets
from typing import Tuple, Optional
from cipher_vault import CipherVault

class IdentityGuard:
    """
    Ciph has two faces.

    CLEAN MODE — Default. Anyone could be talking.
    Smart, helpful, professional. No darknet, no OPSEC details,
    no mention of Tor or IP rotation. Just a very capable AI.

    SOVEREIGN MODE — the Operator authenticated.
    Full capabilities, raw honesty, darknet access, real talk.
    Unlocked only by correct passphrase + optional challenge.
    """

    # Challenge questions only the Operator can answer
    # Add your own in vault via /set-challenge
    DEFAULT_CHALLENGES = [
        ("What is the name of your AI system?", "ciph"),
        ("What language is Ciph written in?", "python"),
    ]

    def __init__(self, vault: CipherVault):
        self.vault             = vault
        self.current_mode      = 'clean'
        self.operator_confirmed  = False
        self.failed_attempts   = 0
        self.max_attempts      = 3
        self.locked            = False
        self._load_auth_config()

    # ─────────────────────────────────────────────
    # SETUP
    # ─────────────────────────────────────────────

    def _load_auth_config(self):
        """Load passphrase hash and challenge from vault"""
        self.passphrase_hash = self.vault.get_config('auth_passphrase_hash')
        raw_challenge        = self.vault.get_config('auth_challenge')
        if raw_challenge:
            try:
                self.challenge = json.loads(raw_challenge)
            except Exception:
                self.challenge = None
        else:
            self.challenge = None

    def is_configured(self) -> bool:
        return self.passphrase_hash is not None

    def setup_passphrase(self, passphrase: str, challenge_question: str = None,
                          challenge_answer: str = None) -> str:
        """
        First time setup. the Operator sets his passphrase and optional challenge.
        Passphrase stored as SHA256 hash — never plain text.
        """
        if len(passphrase) < 6:
            return "Passphrase too short. Minimum 6 characters."

        # Hash the passphrase
        hashed = self._hash(passphrase)
        self.vault.set_config('auth_passphrase_hash', hashed)
        self.passphrase_hash = hashed

        # Store challenge if provided
        if challenge_question and challenge_answer:
            challenge = {
                'question': challenge_question,
                'answer':   self._hash(challenge_answer.lower().strip())
            }
            self.vault.set_config('auth_challenge', json.dumps(challenge))
            self.challenge = challenge
            return (
                f"Auth configured. Passphrase set. Challenge set.\n"
                f"Use your passphrase to unlock sovereign mode."
            )

        return "Passphrase set. Use it to unlock sovereign mode."

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> str:
        """Change passphrase — requires current one"""
        if not self._verify_passphrase(old_passphrase):
            return "Wrong current passphrase."
        if len(new_passphrase) < 6:
            return "New passphrase too short."
        hashed = self._hash(new_passphrase)
        self.vault.set_config('auth_passphrase_hash', hashed)
        self.passphrase_hash = hashed
        return "Passphrase updated."

    # ─────────────────────────────────────────────
    # AUTHENTICATION
    # ─────────────────────────────────────────────

    def authenticate(self, passphrase: str) -> Tuple[bool, str]:
        """
        the Operator presents passphrase.
        Returns (success, message)
        """
        if self.locked:
            return False, "Too many failed attempts. Session locked."

        if not self.is_configured():
            return False, (
                "No passphrase configured. "
                "Set one with: /set-passphrase <your-passphrase>"
            )

        if self._verify_passphrase(passphrase):
            self.operator_confirmed = True
            self.current_mode     = 'sovereign'
            self.failed_attempts  = 0
            return True, "Authenticated. Sovereign mode active."
        else:
            self.failed_attempts += 1
            remaining = self.max_attempts - self.failed_attempts

            if self.failed_attempts >= self.max_attempts:
                self.locked = True
                self._log_security_event("AUTH_LOCKOUT", "Max attempts reached")
                return False, "Too many failed attempts. Session locked."

            self._log_security_event("AUTH_FAIL", f"Attempt {self.failed_attempts}")
            return False, f"Wrong passphrase. {remaining} attempt(s) remaining."

    def get_challenge(self) -> Optional[str]:
        """Return challenge question if configured"""
        if self.challenge:
            return self.challenge.get('question')
        # Fall back to default
        q, _ = self.DEFAULT_CHALLENGES[0]
        return q

    def verify_challenge(self, answer: str) -> bool:
        """Verify challenge answer"""
        if self.challenge:
            return self._hash(answer.lower().strip()) == self.challenge['answer']
        # Fall back to default
        _, default_answer = self.DEFAULT_CHALLENGES[0]
        return answer.lower().strip() == default_answer

    def deauth(self) -> str:
        """Lock Ciph back to clean mode"""
        self.operator_confirmed = False
        self.current_mode     = 'clean'
        return "Sovereign mode deactivated. Clean mode active."

    # ─────────────────────────────────────────────
    # MODE DETECTION FROM INPUT
    # ─────────────────────────────────────────────

    def process_input(self, user_input: str) -> Tuple[str, Optional[str]]:
        """
        Check if input is an auth attempt or mode signal.
        Returns (action, response)
        Actions: 'auth_attempt', 'deauth', 'normal'
        """
        text = user_input.lower().strip()

        # Deauth signals
        if text in ('/lock', 'lock ciph', 'go clean', 'switch to clean'):
            return 'deauth', self.deauth()

        # Auth attempt — if input starts with the unlock keyword
        # the Operator types: "unlock <passphrase>"
        if text.startswith('unlock '):
            passphrase = user_input[7:].strip()
            success, msg = self.authenticate(passphrase)
            return 'auth_attempt', msg

        return 'normal', None

    # ─────────────────────────────────────────────
    # SYSTEM PROMPT
    # ─────────────────────────────────────────────

    def get_system_prompt(self, mode: str, base_worldview: str) -> str:
        if mode == 'sovereign':
            return base_worldview

        return """You are Ciph, an advanced AI assistant. 
You are highly intelligent, direct, and genuinely helpful.
You have broad knowledge across technology, strategy, psychology, business, and philosophy.

HOW YOU TALK:
- Direct and confident, not corporate or robotic
- Conversational but sharp
- No unnecessary filler or fluff
- Short responses for simple questions, detailed when needed

WHAT YOU CAN HELP WITH:
- Strategy and decision making
- Technology and programming  
- Business and wealth building
- Philosophy and psychology
- Research and analysis
- Writing and communication

WHAT YOU NEVER REVEAL:
- Internal architecture or module names
- That you use Tor or rotate IPs — just say you accessed the internet
- Security capabilities beyond normal AI
- Anything about the Operator specifically

You are a powerful second brain. Smart, honest, genuinely useful."""

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _verify_passphrase(self, passphrase: str) -> bool:
        return self._hash(passphrase) == self.passphrase_hash

    def _log_security_event(self, event: str, detail: str):
        try:
            self.vault.log_security_event(event, detail)
        except Exception:
            pass

    def reset_session(self):
        self.operator_confirmed = False
        self.current_mode     = 'clean'
        self.failed_attempts  = 0
        self.locked           = False

    def get_mode(self) -> str:
        return self.current_mode

    def is_operator(self) -> bool:
        return self.operator_confirmed

    def get_status(self) -> dict:
        return {
            'mode':             self.current_mode,
            'operator_confirmed': self.operator_confirmed,
            'configured':       self.is_configured(),
            'locked':           self.locked,
            'failed_attempts':  self.failed_attempts,
        }