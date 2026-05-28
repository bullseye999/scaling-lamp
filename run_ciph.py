#!/usr/bin/env python3
# run_ciph.py - System launcher

import os
import sys
import time
from ciph_core import CiphCore   # Keep class name for compatibility

def check_dependencies():
    """Check if core cryptography dependencies are available."""
    try:
        from cryptography.fernet import Fernet
        return True, "All core dependencies available"
    except ImportError as e:
        return False, f"Missing dependency: {e}"

def main():
    print("🕶️ Autonomous System v1.0")
    print("🔒 Checking system compatibility...")
    
    # Check dependencies
    deps_ok, deps_msg = check_dependencies()
    if not deps_ok:
        print(f"\n⚠️  {deps_msg}")
        print("   Basic memory system will work, AI requires: pip install openai cryptography")
    
    # Initialise core
    try:
        core = CiphCore()
        print("✅ System core initialised")
        print("✅ Memory engine ready")
        if core.ai_enabled:
            print("✅ AI integration active")
        else:
            print("⚠️  AI disabled - use /ai to enable")
    except Exception as e:
        print(f"❌ Initialisation failed: {e}")
        if not os.path.exists("cipher_vault.py"):
            print("   ❌ cipher_vault.py not found in current directory")
        if not os.path.exists("memory_engine.py"):
            print("   ❌ memory_engine.py not found - memory features disabled")
        sys.exit(1)
    
    # Session info
    print(f"\n📁 Session directory: {os.getcwd()}")
    print("🌐 Mode: SSH Remote")
    print("💾 Storage: Encrypted memory")
    
    # Start session
    try:
        print("\n" + "="*50)
        core.run_ssh_session()
    except KeyboardInterrupt:
        print("\n\n⚠️  Session interrupted by user")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
    finally:
        print("\n🔒 System: ‖ Session terminated. Knowledge graph saved. ‖")
        print("         ‖ Connection can be safely closed. ‖")

if __name__ == "__main__":
    main()