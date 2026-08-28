#!/usr/bin/env python3
# ciph_router.py - Primary Direct Router for CIPH (DeepSeek V4 Pro Engine)

"""
========================================================================================
CIPH DIRECT-ENGINE ROUTING ARCHITECTURE (DEEPSEEK V4 PRO)
========================================================================================
Primary Engine: DeepSeek V4 Pro API (https://api.deepseek.com/v1)
- Model: deepseek-chat (V4 / V4-Flash) or deepseek-reasoner
- Direct Cloud Integration: Fast latency (<500ms), massive context window, high reasoning.
- All requests route directly to DeepSeek V4 Pro.

[DEPRECATED: RunPod 8B Local Proxy & Split Routing is commented out for reference]
========================================================================================
"""

import os
import re
import time
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from openai import OpenAI

# ---------------------------------------------------------------------
# Load environment variables from .env file
# ---------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


# Default AI Configuration
DEFAULT_API_BASE_URL = os.environ.get("CIPH_BASE_URL", os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"))
DEFAULT_MODEL = os.environ.get("CIPH_MODEL", os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"))


class CiphRouter:
    """
    Direct-Engine Router for CIPH Sovereign AI.
    Routes queries to the configured LLM API endpoint.
    """
    _warned_missing_key = False

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        proxy_url: Optional[str] = None,
        endpoint_deepseek_id: Optional[str] = None,
        base_url_deepseek: Optional[str] = None,
        model_8b: Optional[str] = None,
        model_deepseek: Optional[str] = None,
    ):
        # API Configuration
        self.api_key = (
            api_key 
            or os.environ.get("CIPH_API_KEY", "")
            or os.environ.get("AI_API_KEY", "")
            or os.environ.get("DEEPSEEK_API_KEY", "") 
            or os.environ.get("OPENAI_API_KEY", "")
            or os.environ.get("RUNPOD_API_KEY", "")
        ).strip()
        
        raw_base = base_url or DEFAULT_API_BASE_URL
        self.base_url = raw_base.rstrip("/")
        if not self.base_url.endswith("/v1"):
            self.base_url = self.base_url + "/v1"
            
        self.model = model or DEFAULT_MODEL

        # Primary Client
        self.client_deepseek: Optional[OpenAI] = None
        self._init_clients()

        # Metrics Tracking
        self.stats: Dict[str, Any] = {
            "total_requests": 0,
            "routes_deepseek_v4": 0,
            "failed_requests": 0,
            "last_route": "none",
            "last_latency_ms": 0.0,
            "avg_latency_ms": 0.0,
            "start_time": time.time()
        }

    def _init_clients(self) -> None:
        """Initialize OpenAI-compatible AI client."""
        if self.api_key:
            try:
                self.client_deepseek = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                    timeout=90.0
                )
            except Exception as e:
                print(f"⚠️ [CiphRouter] Failed to initialize AI client: {e}")
                self.client_deepseek = None
        else:
            self.client_deepseek = None

    def _call_client(
        self,
        client: OpenAI,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 2048
    ) -> str:
        """Execute chat completion request against API endpoint."""
        response = client.chat.completions.create(
            model=model,
            messages=messages,  # type: ignore
            temperature=temperature,
            max_tokens=max_tokens
        )
        if response.choices and len(response.choices) > 0:
            content = response.choices[0].message.content
            return content.strip() if content else ""
        return ""

    def think(
        self,
        user_input: str,
        history: List[Dict[str, str]],
        system_prompt: str,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Main routing entry point.
        """
        start_t = time.time()
        self.stats["total_requests"] += 1
        tokens = max_tokens or 2048

        # Prepare messages payload
        messages = [{"role": "system", "content": system_prompt}]
        for msg in history[-8:]:
            role = msg.get("role", "assistant")
            if role in ["user", "assistant"]:
                messages.append({"role": role, "content": msg.get("content", "")})
        messages.append({"role": "user", "content": user_input})

        response_text = ""
        route_taken = "AI-Core"

        if self.client_deepseek:
            try:
                response_text = self._call_client(
                    client=self.client_deepseek,
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=tokens
                )
                if response_text:
                    self.stats["routes_deepseek_v4"] += 1
            except Exception as e:
                print(f"⚠️ [CiphRouter] AI API request failed ({e})")
                self.stats["failed_requests"] += 1
                response_text = f"[CiphRouter Error: AI API request failed: {e}]"
        else:
            self.stats["failed_requests"] += 1
            response_text = (
                "[AI Engine Notice: API key not configured. "
                "Set your API key via /setkey <key> to enable generative AI reasoning.]"
            )

        # Track metrics
        latency = (time.time() - start_t) * 1000.0
        self.stats["last_route"] = route_taken
        self.stats["last_latency_ms"] = round(latency, 2)
        total = self.stats["total_requests"]
        prev_avg = self.stats["avg_latency_ms"]
        self.stats["avg_latency_ms"] = round(((prev_avg * (total - 1)) + latency) / total, 2)

        return response_text

    def test_ai(self) -> Dict[str, Any]:
        """Send a test health ping to the AI API."""
        if not self.api_key:
            return {"success": False, "error": "API key is not configured. Set it via /setkey <key> or in .env."}

        try:
            t0 = time.time()
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5
            }
            resp = requests.post(f"{self.base_url}/chat/completions", json=payload, headers=headers, timeout=15)
            latency = round((time.time() - t0) * 1000, 2)
            if resp.status_code == 200:
                return {
                    "success": True,
                    "model": self.model,
                    "base_url": self.base_url,
                    "latency_ms": latency,
                    "message": "✅ AI Engine Active & Connected"
                }
            return {
                "success": False,
                "status_code": resp.status_code,
                "error": resp.text[:200]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def test_deepseek(self) -> Dict[str, Any]:
        """Alias for backward compatibility."""
        return self.test_ai()

    def check_health(self) -> Dict[str, Any]:
        """Check status of AI endpoint."""
        return {
            "ai_status": "online" if self.client_deepseek else "missing_key",
            "model": self.model,
            "base_url": self.base_url
        }

    def get_status(self) -> Dict[str, Any]:
        """Return AI routing configuration, metrics, and health."""
        uptime = round(time.time() - self.stats["start_time"], 1)
        return {
            "primary_engine": "Sovereign AI",
            "model": self.model,
            "base_url": self.base_url,
            "api_key_configured": bool(self.api_key),
            "stats": self.stats,
            "uptime_seconds": uptime,
            "health": self.check_health()
        }

    def get_status_formatted(self) -> str:
        """Return formatted summary for CLI and status displays."""
        s = self.stats
        key_preview = (self.api_key[:6] + "..." + self.api_key[-4:]) if len(self.api_key) > 10 else "NOT CONFIGURED"
        return (
            "‖ CIPH AI ENGINE STATUS ‖\n"
            f"• Active Model      : {self.model}\n"
            f"• Endpoint Base URL : {self.base_url}\n"
            f"• API Key (.env)    : {key_preview}\n"
            f"• Total Requests    : {s['total_requests']} (Success: {s['routes_deepseek_v4']} | Failed: {s['failed_requests']})\n"
            f"• Last Latency      : {s['last_latency_ms']} ms (Avg: {s['avg_latency_ms']} ms)"
        )


if __name__ == "__main__":
    import sys
    router = CiphRouter()
    print(router.get_status_formatted())
    print()
    ping = router.test_deepseek()
    print("Ping Test Result:", ping)
