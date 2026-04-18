# main.py
from core.config import settings

def main():
    print("Code Review MCP Server")
    print(f"Running on {settings.host}:{settings.port}")
    print(f"Debug mode: {settings.debug}")
    print("Config loaded successfully ✓")

if __name__ == "__main__":
    main()