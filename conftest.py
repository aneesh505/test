import sys
from pathlib import Path

# Makes `from app import ...` work no matter where pytest is started from.
sys.path.insert(0, str(Path(__file__).parent))
