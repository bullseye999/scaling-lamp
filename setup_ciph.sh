#!/bin/bash
echo "🚀 CIPH ENVIRONMENT SETUP"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv ciph_env

# Activate environment
echo "🔧 Activating environment..."
source ciph_env/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install cryptography feedparser pyyaml requests

# Fix file permissions
echo "🔒 Setting permissions..."
chmod +x *.py

# Test installation
echo "🧪 Testing installation..."
python3 -c "
from cipher_vault import CipherVault
vault = CipherVault()
vault.store_conversation('test', 'Ciph environment ready')
print('✅ Virtual environment setup complete')
print('✅ Dependencies installed')
print('✅ System ready for deployment')
"

echo ""
echo "🎯 SETUP COMPLETE!"
echo "💡 Always run: source ciph_env/bin/activate"
echo "💡 Then run: python3 ciph_core.py"