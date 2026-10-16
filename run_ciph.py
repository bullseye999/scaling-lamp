#!/usr/bin/env python3
# run_ciph.py - Enhanced launcher

import os
import sys

# Enable ANSI escape sequences on Windows
if sys.platform == "win32":
    os.system("")

import time
from ciph_core import CiphCore

def check_dependencies():
    """Check if all required dependencies are available"""
    try:
        import openai
        import cryptography
        from cryptography.fernet import Fernet
        return True, "All dependencies available"
    except ImportError as e:
        return False, f"Missing dependency: {e}"

def main():
    print("🕶️ CIPH 3.0 - Sovereign Autonomous Intelligence")
    print("🔒 Checking system compatibility...")
    
    # Check dependencies
    deps_ok, deps_msg = check_dependencies()
    if not deps_ok:
        print(f"\n⚠️  {deps_msg}")
        print("   Basic memory system will work, AI requires: pip install openai cryptography")
    
    # Initialize Ciph
    try:
        ciph = CiphCore()
        print("✅ Ciph core initialized")
        print("✅ Enhanced memory engine ready")
        if ciph.ai_enabled:
            print("✅ AI integration active")
        else:
            print("⚠️  AI disabled - use /ai to enable")
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        if not os.path.exists("cipher_vault.py"):
            print("   ❌ cipher_vault.py not found in current directory")
        if not os.path.exists("memory_engine.py"):
            print("   ❌ memory_engine.py not found - enhanced memory disabled")
        sys.exit(1)
    
    # Session info
    print(f"\n📁 Session directory: {os.getcwd()}")
    print("🌐 Mode: SSH Remote")
    print("💾 Storage: Enhanced encrypted memory")
    
    # Start the session
    try:
        print("\n" + "="*50)
        ciph.run_ssh_session()
    except KeyboardInterrupt:
        print("\n\n⚠️  Session interrupted by user")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
    finally:
        print("\n🔒 Ciph: ‖ Session terminated. Knowledge graph saved. ‖")
        print("         ‖ Connection can be safely closed. ‖")

if __name__ == "__main__":
    main()