#!/usr/bin/env python3
# test_dialogue.py - Test the new conversation engine

from enhanced_conversation import CiphConversation
from cipher_vault import CipherVault

def test_conversation():
    # Throwaway vault: the default path is the operator's live vault, and this module runs at
    # discovery time in whatever directory the suite was started from.
    import tempfile
    root = tempfile.mkdtemp(prefix="ciph_dialogue_test_")
    vault = CipherVault(f"{root}/vault.db", f"{root}/key", f"{root}/salt")
    ciph = CiphConversation(vault)
    
    test_inputs = [
        "yo what's the move for tonight",
        "how do we make money fast",
        "im frustrated with this shit not working",
        "analyze the current market for me",
        "give me a strategic plan to hack company x",
        "feel me?",
        "reality check: we broke af right now"
    ]
    
    print("🧪 TESTING CIPH DIALOGUE ENGINE")
    print("=" * 50)
    
    for user_input in test_inputs:
        print(f"\nYou: {user_input}")
        response = ciph.process_input(user_input)
        print(f"Ciph: {response}")
        print("-" * 50)
    
    print(f"\n💭 Conversation summary: {ciph.get_conversation_summary()}")

if __name__ == "__main__":
    test_conversation()