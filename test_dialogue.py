#!/usr/bin/env python3
# test_dialogue.py - Test the new conversation engine

from enhanced_conversation import CiphConversation
from cipher_vault import CipherVault

def test_conversation():
    vault = CipherVault()
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