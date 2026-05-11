# main.py
import uvicorn
from core.config import settings

if __name__ == "__main__":
    print(f"Starting Code Review MCP Server on {settings.host}:{settings.port}")
    uvicorn.run(
        "api.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,    
    )