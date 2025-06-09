from fastapi import FastAPI, HTTPException, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
from phish_detector import PhishingDetector
import asyncio
from urllib.parse import urlparse
from datetime import datetime
import re

app = FastAPI(
    title="PhishEvil API",
    description="A comprehensive phishing detection API that analyzes URLs for potential threats",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

class URLRequest(BaseModel):
    urls: List[str]

    def clean_urls(self) -> List[str]:
        cleaned = []
        for url in self.urls:
            url = url.strip()
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                cleaned.append(url)
        return cleaned

class URLResponse(BaseModel):
    url: str
    total_score: float
    risk_level: str
    details: list[str]

class PhishingURLResponse(BaseModel):
    url: str
    first_detected: datetime
    last_verified: datetime
    details: List[str]
    score: int
    verified_count: int

detector = PhishingDetector()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Serve the main page with the URL analysis form
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_model=List[URLResponse])
async def analyze_urls(request: URLRequest):
    """
    Analyze multiple URLs for potential phishing threats.
    Returns a risk score and detailed analysis for each URL.
    """
    try:
        # Clean and validate URLs
        urls = request.clean_urls()
        if not urls:
            raise HTTPException(status_code=400, detail="No valid URLs provided")

        # Analyze URLs concurrently
        tasks = [detector.analyze_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle any errors
        processed_results = []
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                processed_results.append({
                    "url": url,
                    "total_score": 0,
                    "risk_level": "Error",
                    "details": [f"Error analyzing URL: {str(result)}"]
                })
            else:
                processed_results.append(result)

        return processed_results

    except Exception as e:
        # Ensure cleanup in case of errors
        if hasattr(detector, 'vt_client') and detector.vt_client:
            await detector.close_vt_client()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/phishing", response_model=List[PhishingURLResponse])
async def get_phishing_urls(limit: int = 100):
    """
    Get a list of recently detected phishing URLs
    """
    try:
        return detector.db.get_recent_phishing_urls(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving phishing URLs: {str(e)}")

@app.get("/check/{url:path}", response_model=Dict)
async def quick_check(url: str):
    """
    Quickly check if a URL is a known phishing URL
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Parse the URL to check both domain and full path
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        full_path = parsed_url.path + parsed_url.query + parsed_url.fragment
        
        # First check cache and known phishing URLs for exact URL match
        cached = detector.db.get_cached_result(url)
        if cached:
            return {
                "url": url,
                "is_phishing": cached["risk_level"] == "High Risk",
                "cached": True,
                "details": cached["details"],
                "full_check": True
            }
            
        # Check if exact URL is known phishing
        known_phishing = detector.db.is_known_phishing(url)
        if known_phishing:
            return {
                "url": url,
                "is_phishing": True,
                "cached": False,
                "details": [
                    "🚫 KNOWN PHISHING URL",
                    f"First detected: {known_phishing['first_detected']}",
                    f"Verified {known_phishing['verified_count']} times"
                ],
                "full_check": True
            }

        # If not found, perform a quick analysis
        score = 100
        details = []
        
        # Check domain reputation
        domain_check = await detector.check_domain_reputation(url)
        score += domain_check["score"]
        details.extend(domain_check.get("reasons", []))
        
        # Check URL structure (including path)
        url_check = detector.check_url_structure(url)
        score += url_check["score"]
        details.extend(url_check.get("reasons", []))
        
        # Additional checks for path and parameters
        if full_path:
            # Check for suspicious patterns in path
            suspicious_patterns = [
                "login", "signin", "account", "password", "reset", "verify",
                "update", "secure", "auth", "confirm", "wallet", "payment"
            ]
            pattern_count = sum(1 for pattern in suspicious_patterns if pattern in full_path.lower())
            if pattern_count > 2:
                score -= 20
                details.append(f"Multiple suspicious terms in URL path: {pattern_count} found")
            
            # Check for excessive parameters
            if len(parsed_url.query) > 200:
                score -= 10
                details.append("Unusually long query parameters")
            
            # Check for obfuscated or encoded content
            encoded_chars = re.findall(r'%[0-9A-Fa-f]{2}', full_path)
            if len(encoded_chars) > 5:
                score -= 15
                details.append("Multiple encoded characters in URL path")
            
            # Check for suspicious file extensions
            suspicious_extensions = [".exe", ".zip", ".scr", ".js", ".php"]
            if any(ext in full_path.lower() for ext in suspicious_extensions):
                score -= 25
                details.append("Suspicious file extension in URL")

        # Normalize score
        score = max(0, min(100, score))
        
        # Determine risk level
        is_phishing = score < 60
        
        result = {
            "url": url,
            "is_phishing": is_phishing,
            "cached": False,
            "details": details,
            "score": score,
            "full_check": True
        }
        
        # Cache the result
        detector.db.cache_result(url, {
            "risk_level": "High Risk" if is_phishing else "Low Risk",
            "total_score": score,
            "details": details
        })
            
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking URL: {str(e)}") 