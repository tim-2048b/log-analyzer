"""Enables: python -m analyzer <file> [options]"""

print("Running mytool")
from .cli import main

if __name__ == "__main__":
    main()
