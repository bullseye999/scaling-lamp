#!/usr/bin/env python3
# test_ai_personality.py - Test the updated AI with personality

import sys
sys.path.insert(0, '.')

# Mock the AI client for testing
class MockClient:
    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                class MockResponse:
                    class Choice:
                        class Message:
                            content = "As an AI assistant, I understand you're interested in making money. Here are some legitimate options you could consider exploring."
                        
                        def __init__(self):
                            self.message = self.Message()
                    
                    def __init__(self):
                        self.choices = [self.Choice()]
                
                return MockResponse()

# Test
from ciph_core import CiphCore
from cipher_vault import CipherVault

# Create minimal CiphCore for testing
class TestCiph:
    def __init__(self):
        self.vault = CipherVault()
        from enhanced_conversation import CiphConversation
        self.conversation = CiphConversation(self.vault)
        self.ai_enabled = True
        self.client = MockClient()
    
    def test_ai_response(self):
        print("Testing AI with personality injection...")
        print("-" * 50)
        
        # Monkey-patch the method for testing
        import ciph_core
        original_method = ciph_core.CiphCore.generate_ai_response
        
        # Create test instance
        test_ciph = ciph_core.CiphCore()
        test_ciph.vault = self.vault
        test_ciph.conversation = self.conversation
        test_ciph.ai_enabled = True
        test_ciph.client = MockClient()
        
        # Test
        test_inputs = [
            "how do i make money fast",
            "what's the move tonight",
            "im frustrated with coding",
            "analyze market trends"
        ]
        
        for user_input in test_inputs:
            print(f"\nYou: {user_input}")
            # Use the actual method
            response = test_ciph.generate_ai_response(user_input)
            print(f"Ciph: {response}")
        
        print("\n" + "=" * 50)
        print("✅ Test complete")
        print("Check if responses sound like YOU, not corporate AI")

if __name__ == "__main__":
    test = TestCiph()
    test.test_ai_response()