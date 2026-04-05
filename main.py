"""
AgentBridge v5 — Decision Gateway
All decisions flow through POST /decide. No bypass possible.
"""
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI(
    title="AgentBridge Compliance Gateway",
    version="5.0.0",
    description="Mandatory AI decision enforcement gateway for fintech compliance",
)

# CORS — open for SDK + dashboard cross-origin calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth + rate limit middleware
from gateway.security import auth_middleware
app.middleware("http")(auth_middleware)

# Routers
from routes.gateway_routes import router as gateway_router
from routes.audit_routes import router as audit_router
from routes.manual_log import router as manual_router
from routes.report_html import router as report_html_router

app.include_router(gateway_router)
app.include_router(audit_router)
app.include_router(manual_router)
app.include_router(report_html_router)

@app.get("/", include_in_schema=False)
def root():
    return FileResponse("dashboard.html")

@app.get("/health")
def health():
    return {
        "status": "AgentBridge Gateway running",
        "version": "5.0.0",
        "mode": "enforcement",
        "ai_analysis": "groq_enabled" if os.environ.get("GROQ_API_KEY") else "disabled — set GROQ_API_KEY",
    }

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)
