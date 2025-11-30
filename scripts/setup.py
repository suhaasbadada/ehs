# scripts/setup.py
"""Setup script for development environment"""

import subprocess
import sys

def setup():
    """Setup development environment"""
    print("Setting up Secure E-Health System...")
    
    # Install dependencies
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    print("✅ Setup complete!")

if __name__ == "__main__":
    setup()
