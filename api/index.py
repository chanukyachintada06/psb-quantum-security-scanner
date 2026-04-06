import sys
import os

# Add the 'backend' directory to the Python path
# This allows Vercel to correctly resolve imports like `import database`
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from main import app
