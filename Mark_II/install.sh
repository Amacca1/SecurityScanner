#!/bin/bash
# Security Scanner Mark II - Quick Installation Script

echo "🔒 Security Scanner Mark II - Quick Install"
echo "=========================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python 3 found"

# Check if pip is available
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "❌ pip is required but not installed"
    exit 1
fi

echo "✅ pip found"

# Install dependencies
echo "📦 Installing Python dependencies..."
python3 -m pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Make scripts executable
chmod +x security_scanner.py
chmod +x setup.py
chmod +x install_hooks.py
chmod +x test_scanner.py

echo "✅ Scripts made executable"

# Run quick test
echo "🧪 Running quick test..."
python3 test_scanner.py

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Next steps:"
echo "1. Run the setup: python3 setup.py"
echo "2. Configure your .env file with API keys"
echo "3. Install git hooks: python3 install_hooks.py --local"
echo ""
echo "For detailed instructions, see README.md"
