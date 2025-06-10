import re
import ssl
import socket
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
from thefuzz import fuzz
from typing import Dict, List, Optional
import aiohttp
import asyncio
from dotenv import load_dotenv
import os
import vt
from collections import Counter
import backoff
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

class PhishingDetector:
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        # Clean and validate Google Safe Browsing API key
        raw_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '').strip()
        self.google_sb_api_key = raw_key.rstrip('~') if raw_key else None
        if self.google_sb_api_key:
            logger.info("Google Safe Browsing API key loaded successfully")
        else:
            logger.warning("Google Safe Browsing API key not found in environment variables")
        self._vt_client = None
        
        # Add browser-specific URLs that are always safe
        self.safe_browser_urls = {
            'chrome://', 'about:', 'file://', 'view-source:', 'data:', 'blob:',
            'edge://', 'brave://', 'opera://', 'vivaldi://', 'moz-extension://',
            'chrome-extension://', 'edge-extension://'
        }
        
        # Critical security vendors (highest reputation)
        self.critical_vendors = {
            'ESET': ['Phishing', 'Malware'],
            'Kaspersky': ['Phishing', 'Malware'],
            'BitDefender': ['Malware', 'Phishing'],
            'Fortinet': ['Phishing', 'Malware'],
            'Sophos': ['Phishing', 'Malware'],
            'PhishLabs': ['Phishing'],
            'Phishtank': ['Phishing'],
            'OpenPhish': ['Phishing'],
            'Netcraft': ['Malicious', 'Phishing'],
            'EmergingThreats': ['Clean', 'Malware'],
            'Trustwave': ['Phishing', 'Malware'],
            'AlienVault': ['Clean', 'Malicious'],
            'Google Safebrowsing': ['Clean', 'Malicious']
        }
        
        # Important security vendors (medium reputation)
        self.important_vendors = {
            'Acronis': ['Clean', 'Malicious'],
            'ADMINUSLabs': ['Clean', 'Malicious'],
            'Antiy-AVL': ['Clean', 'Malicious'],
            'Dr.Web': ['Clean', 'Malicious'],
            'G-Data': ['Malware', 'Clean'],
            'Sucuri SiteCheck': ['Clean', 'Malicious'],
            'Quttera': ['Clean', 'Malicious'],
            'Rising': ['Clean', 'Malicious'],
            'Quick Heal': ['Clean', 'Malicious'],
            'malwares.com URL checker': ['Clean', 'Malicious'],
            'Phishing Database': ['Clean', 'Phishing']
        }

        # Additional vendors for broader coverage
        self.additional_vendors = {
            'alphaMountain.ai': ['Phishing', 'Malicious'],
            'ArcSight': ['Malicious'],
            'CyRadar': ['Phishing'],
            'Emsisoft': ['Phishing'],
            'Forcepoint ThreatSeeker': ['Phishing'],
            'Lionic': ['Phishing'],
            'VIPRE': ['Malware'],
            'Webroot': ['Malicious']
        }
        
        # Base domains and their legitimate TLD variants
        self.trusted_domain_patterns = {
            'google': ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp'],
            'facebook': ['facebook.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp'],
            'microsoft': ['microsoft.com'],
            'apple': ['apple.com'],
            'paypal': ['paypal.com'],
            'netflix': ['netflix.com'],
            'instagram': ['instagram.com'],
            'twitter': ['twitter.com'],
            'linkedin': ['linkedin.com'],
            'github': ['github.com'],
            'youtube': ['youtube.com'],
            'yahoo': ['yahoo.com'],
            'wordpress': ['wordpress.com'],
            'adobe': ['adobe.com'],
            'dropbox': ['dropbox.com'],
            'spotify': ['spotify.com'],
            'slack': ['slack.com'],
            'zoom': ['zoom.us'],
            'office': ['office.com']
        }
        
        # Flatten trusted domains for quick lookup
        self.trusted_domains = [domain for domains in self.trusted_domain_patterns.values() for domain in domains]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
            'cli.gs', 'pic.gd', 'DwarfURL.com', 'ow.ly', 'snipurl.com'
        ]

        # Add educational TLDs
        self.trusted_tlds = {
            'edu', 'ac.in', 'edu.in', 'ac.uk', 'edu.au'
        }
        
        # Add trusted educational domains
        self.trusted_edu_domains = {
            'srmist.edu.in',
            'srmiststudentportal'
        }

    @property
    def vt_client(self):
        if self._vt_client is None and self.vt_api_key:
            try:
                self._vt_client = vt.Client(self.vt_api_key)
            except Exception as e:
                print(f"Error initializing VirusTotal client: {str(e)}")
                return None
        return self._vt_client

    async def close_vt_client(self):
        if self._vt_client:
            try:
                await self._vt_client.close_async()
            except Exception as e:
                print(f"Error closing VirusTotal client: {str(e)}")
            finally:
                self._vt_client = None

    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError, vt.APIError, ssl.SSLError),
        max_tries=3,
        max_time=30
    )
    async def analyze_url_with_vt(self, url: str) -> Dict:
        client = None
        try:
            # Create a new client for each request
            client = vt.Client(self.vt_api_key) if self.vt_api_key else None
            if not client:
                return {
                    "success": False,
                    "error": "VirusTotal API key not configured"
                }

            # Get URL ID for VirusTotal API
            url_id = vt.url_id(url)
            
            # First try to get existing analysis
            try:
                url_analysis = await client.get_object_async(f"/urls/{url_id}")
                if not hasattr(url_analysis, 'last_analysis_results'):
                    # If no existing analysis, submit URL for scanning
                    scan_response = await client.scan_url_async(url)
                    await asyncio.sleep(3)  # Give some time for initial analysis
                    url_analysis = await client.get_object_async(f"/urls/{url_id}")
            except vt.APIError as e:
                if "not found" in str(e).lower():
                    # URL not found, submit for scanning
                    scan_response = await client.scan_url_async(url)
                    await asyncio.sleep(3)
                    url_analysis = await client.get_object_async(f"/urls/{url_id}")
                else:
                    raise

            results = {
                "success": True,
                "last_analysis_results": getattr(url_analysis, 'last_analysis_results', {}),
                "reputation": getattr(url_analysis, 'reputation', 0),
                "times_submitted": getattr(url_analysis, 'times_submitted', 0),
                "last_analysis_stats": getattr(url_analysis, 'last_analysis_stats', {})
            }
            
            return results

        except Exception as e:
            return {
                "success": False,
                "error": f"Error analyzing URL with VirusTotal: {str(e)}"
            }
        finally:
            if client:
                await client.close_async()

    async def check_security_vendors(self, url: str) -> Dict:
        score = 0
        reasons = []
        vendor_results = []
        
        if not self.vt_api_key:
            reasons.append("⚠️ Security vendor check skipped - API key not configured")
            return {"score": score, "reasons": reasons, "vendor_results": vendor_results}
        
        vt_results = await self.analyze_url_with_vt(url)
        
        if not vt_results["success"]:
            reasons.append(vt_results.get("error", "⚠️ Error during security vendor analysis"))
            return {"score": score, "reasons": reasons, "vendor_results": vendor_results}
        
        if vt_results.get("last_analysis_results"):
            malicious_critical = 0
            malicious_important = 0
            malicious_additional = 0
            clean_critical = 0
            clean_important = 0
            
            # Process vendor results
            for vendor, result in vt_results["last_analysis_results"].items():
                category = result.get('category', '').lower()
                result_type = result.get('result', '').lower()
                
                # Check critical vendors
                if vendor in self.critical_vendors:
                    if category in ['malicious', 'phishing'] or 'phish' in result_type or 'malware' in result_type:
                        malicious_critical += 1
                        vendor_results.append(f"⚠️ {vendor}: {result.get('result', 'Malicious')}")
                    elif category == 'clean':
                        clean_critical += 1
                
                # Check important vendors
                elif vendor in self.important_vendors:
                    if category in ['malicious', 'phishing'] or 'phish' in result_type or 'malware' in result_type:
                        malicious_important += 1
                        vendor_results.append(f"⚠️ {vendor}: {result.get('result', 'Malicious')}")
                    elif category == 'clean':
                        clean_important += 1
                
                # Check additional vendors
                elif vendor in self.additional_vendors:
                    if category in ['malicious', 'phishing'] or 'phish' in result_type or 'malware' in result_type:
                        malicious_additional += 1
                        vendor_results.append(f"⚠️ {vendor}: {result.get('result', 'Malicious')}")
            
            # Calculate score based on vendor detections
            if malicious_critical > 0:
                score += min(50, malicious_critical * 10)  # Max 50 points from critical vendors
                reasons.append(f"⚠️ CRITICAL: {malicious_critical} high-reputation security vendors detected threats")
            
            if malicious_important > 0:
                score += min(30, malicious_important * 5)  # Max 30 points from important vendors
                reasons.append(f"⚠️ {malicious_important} security vendors detected threats")
            
            if malicious_additional > 0:
                score += min(20, malicious_additional * 3)  # Max 20 points from additional vendors
                reasons.append(f"⚠️ {malicious_additional} additional vendors detected threats")
            
            # Reduce score if many trusted vendors mark it as clean
            if clean_critical > 5 and malicious_critical == 0:
                score -= 20
                reasons.append(f"✅ {clean_critical} high-reputation vendors verified this URL as safe")
            
            if clean_important > 5 and malicious_important == 0:
                score -= 10
                reasons.append(f"✅ {clean_important} security vendors verified this URL as safe")

        return {"score": score, "reasons": reasons, "vendor_results": vendor_results}

    async def check_google_safe_browsing(self, url: str) -> bool:
        """Returns True if the URL is flagged as unsafe by Google Safe Browsing."""
        if not self.google_sb_api_key:
            logger.warning("Google Safe Browsing API key not configured")
            return False
            
        api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_sb_api_key}'
        payload = {
            "client": {
                "clientId": "phish-evil-app",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return bool(data.get("matches"))
                    elif resp.status == 400:
                        error_data = await resp.json()
                        if "error" in error_data and error_data["error"].get("status") == "INVALID_ARGUMENT":
                            logger.error(f"Invalid Google Safe Browsing API key: {error_data['error'].get('message')}")
                        else:
                            logger.error(f"Google Safe Browsing API error: {error_data}")
                    else:
                        logger.error(f"Google Safe Browsing API returned status code: {resp.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Google Safe Browsing check network/timeout error: {str(e)}")
        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {str(e)}")
        return False

    async def analyze_url(self, url: str) -> Dict:
        try:
            # Quick check for browser-specific URLs
            if any(url.startswith(prefix) for prefix in self.safe_browser_urls):
                return {
                    'url': url,
                    'safety_status': 'SAFE',
                    'main_message': '✅ This is a legitimate browser URL',
                    'details': ['✅ Browser-specific URL (chrome://, about:, etc.)'],
                    'vendor_alerts': [],
                    'gsb_checked': False,
                    'virustotal_checked': False
                }

            # Always check Google Safe Browsing
            gsb_flagged = await self.check_google_safe_browsing(url)
            gsb_details = []
            if gsb_flagged:
                gsb_details.append('🚨 Flagged by Google Safe Browsing')

            # Always check VirusTotal, but with a timeout
            vt_result = None
            vt_flagged = False
            vt_details = []
            vt_vendor_alerts = []
            vt_timeout = False
            try:
                vt_result = await asyncio.wait_for(self.check_security_vendors(url), timeout=3)
                vt_flagged = vt_result['score'] > 0
                vt_details = vt_result['reasons']
                vt_vendor_alerts = vt_result.get('vendor_results', [])
            except asyncio.TimeoutError:
                vt_timeout = True
                vt_details.append('⚠️ VirusTotal check timed out')

            # Aggregate results
            is_dangerous = gsb_flagged or vt_flagged
            reasons = []
            vendor_alerts = []
            if gsb_details:
                reasons.extend(gsb_details)
            if vt_details:
                reasons.extend(vt_details)
            if vt_vendor_alerts:
                vendor_alerts.extend(vt_vendor_alerts)

            # Parse URL for details
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            protocol = parsed_url.scheme
            path = parsed_url.path
            port = parsed_url.port if parsed_url.port else (443 if protocol == 'https' else 80)

            # Main message
            if is_dangerous:
                if gsb_flagged and vt_flagged:
                    main_message = '🚨 This link is flagged as dangerous by both Google Safe Browsing and VirusTotal!'
                elif gsb_flagged:
                    main_message = '🚨 This link is flagged as dangerous by Google Safe Browsing!'
                elif vt_flagged:
                    main_message = '🚨 This link is flagged as dangerous by VirusTotal!'
                else:
                    main_message = '⚠️ This website shows suspicious characteristics.'
            else:
                main_message = '✅ This website appears to be safe'
            
            return {
                'url': url,
                'domain': domain,
                'protocol': protocol,
                'path': path,
                'port': port,
                'risk_level': 'High Risk' if is_dangerous else 'Low Risk',
                'total_score': 100 if is_dangerous else 0,
                'features': {
                    'reasons': reasons,
                    'vendor_alerts': vendor_alerts,
                    'main_message': main_message
                },
                'gsb_checked': True,
                'virustotal_checked': not vt_timeout
            }
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            raise

    async def check_domain_reputation(self, url: str) -> Dict:
        domain = urlparse(url).netloc
        score = 0
        reasons = []
        vendor_results = []

        if not self.vt_api_key:
            reasons.append("VirusTotal API key not configured")
            return {"score": score, "reasons": reasons, "vendor_results": vendor_results}

        vt_results = await self.analyze_url_with_vt(url)
        
        if not vt_results["success"]:
            reasons.append(vt_results.get("error", "Unknown error during VirusTotal analysis"))
            return {"score": score, "reasons": reasons, "vendor_results": vendor_results}

        # Process vendor results
        if vt_results.get("last_analysis_results"):
            vendor_stats = {'malicious': [], 'clean': [], 'suspicious': [], 'unrated': []}
            
            for vendor, result in vt_results["last_analysis_results"].items():
                category = result.get('category', 'unrated').lower()
                if category in vendor_stats:
                    vendor_stats[category].append(vendor)
            
            # Process critical and important vendors
            critical_malicious = len([v for v in vendor_stats['malicious'] if v in self.critical_vendors])
            critical_clean = len([v for v in vendor_stats['clean'] if v in self.critical_vendors])
            important_malicious = len([v for v in vendor_stats['malicious'] if v in self.important_vendors])
            important_clean = len([v for v in vendor_stats['clean'] if v in self.important_vendors])
            
            # Adjust scores based on vendor verdicts
            if critical_malicious > 0:
                score -= 40
                reasons.append(f"{critical_malicious} critical security vendors flagged this URL as malicious")
                vendor_results.extend([v for v in vendor_stats['malicious'] if v in self.critical_vendors])
            
            if important_malicious > 0:
                score -= 20
                reasons.append(f"{important_malicious} important security vendors flagged this URL as malicious")
            
            if len(vendor_stats['suspicious']) > 0:
                score -= 10
                reasons.append(f"{len(vendor_stats['suspicious'])} vendors marked this URL as suspicious")
            
            if critical_clean > 5:
                score += 20
                reasons.append(f"{critical_clean} critical security vendors verified this URL as clean")
            
            if important_clean > 5:
                score += 10
                reasons.append(f"{important_clean} important security vendors verified this URL as clean")

            # Add reputation score if available
            reputation = vt_results.get("reputation", 0)
            if reputation is not None:
                if reputation <= -50:
                    score -= 30
                    reasons.append("Domain has very poor reputation on VirusTotal")
                elif reputation >= 50:
                    score += 20
                    reasons.append("Domain has excellent reputation on VirusTotal")

        return {"score": score, "reasons": reasons, "vendor_results": vendor_results}

    def check_domain_age(self, url: str) -> Dict:
        domain = urlparse(url).netloc.split(':')[0]  # Remove port if present
        score = 0
        reasons = []
        
        # Remove www prefix for whois lookup
        domain = re.sub(r'^www\.', '', domain)
        
        # First check if it's a known trusted domain
        base_domain = domain.split('.')[0]
        if base_domain in self.trusted_domain_patterns and domain in self.trusted_domains:
            score += 10
            reasons.append("✅ Well-established trusted domain")
            return {"score": score, "reasons": reasons}
        
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(creation_date, datetime):
                    domain_age = (datetime.now() - creation_date).days
                    if domain_age == 0:
                        score -= 100
                        reasons.append("⚠️ CRITICAL: Domain was registered today (0 days old) - Highly likely to be phishing")
                    elif domain_age < 7:
                        score -= 50
                        reasons.append(f"⚠️ Very suspicious: Domain is only {domain_age} days old")
                    elif domain_age < 30:
                        score -= 30
                        reasons.append(f"Warning: Domain is very new ({domain_age} days old)")
                    elif domain_age < 90:
                        score -= 10
                        reasons.append(f"Notice: Domain is relatively new ({domain_age} days old)")
                    elif domain_age > 365:
                        score += 10
                        reasons.append(f"✅ Domain is well established ({domain_age} days old)")
                    else:
                        reasons.append(f"Domain age: {domain_age} days")
                else:
                    # If we can't determine exact age but have a creation date
                    score -= 5
                    reasons.append("Notice: Could not determine exact domain age")
            else:
                # For some well-known TLDs, whois might not return creation date
                if any(domain.endswith(tld) for tld in ['.com', '.org', '.net', '.edu', '.gov', '.co.in', '.co.uk']):
                    reasons.append("Common TLD - age verification skipped")
                else:
                    score -= 20
                    reasons.append("Warning: No domain creation date found")
        except Exception as e:
            if "No match for domain" in str(e):
                score -= 50
                reasons.append("⚠️ Domain does not exist in WHOIS database")
            else:
                # Don't penalize as heavily for WHOIS lookup failures
                score -= 5
                reasons.append(f"Notice: Could not verify domain age")

        return {"score": score, "reasons": reasons}

    def check_url_structure(self, url: str) -> Dict:
        parsed_url = urlparse(url)
        path = parsed_url.path
        score = 0
        reasons = []

        # Check for multiple subdomains (often used in phishing)
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 4: # e.g., sub.sub.domain.com
            score -= 15
            reasons.append("⚠️ URL contains excessive subdomains")

        # Check for long URL length (often used to hide real domain)
        if len(url) > 75:
            score -= 10
            reasons.append("⚠️ URL is unusually long")

        # Check for suspicious characters in path (e.g., @, non-standard encoding)
        suspicious_chars_regex = r"[@=?&%\']"
        if re.search(suspicious_chars_regex, path):
            score -= 10
            reasons.append("⚠️ Suspicious characters in URL path")
            
        return {"score": score, "reasons": reasons}

    def is_ip_address_url(self, url: str) -> bool:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            try:
                socket.inet_aton(hostname)
                return True
            except socket.error:
                pass
        return False

    def has_at_symbol_in_domain(self, url: str) -> bool:
        parsed_url = urlparse(url)
        # Check if '@' is present in the network location (hostname and port)
        return '@' in parsed_url.netloc

    def check_domain_similarity(self, url: str) -> Dict:
        domain = urlparse(url).netloc.lower()
        score = 0
        reasons = []
        
        # Remove common prefixes and get the clean domain
        domain = re.sub(r'^(www\.|mail\.|login\.)', '', domain)
        
        # If domain is in trusted list, it's safe
        if domain in self.trusted_domains:
            reasons.append("Trusted domain")
            score += 10
            return {"score": score, "reasons": reasons}
        
        # Also check without www prefix in trusted domains
        for trusted_domain in self.trusted_domains:
            if domain == trusted_domain or domain == re.sub(r'^www\.', '', trusted_domain):
                reasons.append("Trusted domain")
                score += 10
                return {"score": score, "reasons": reasons}
        
        # Extract base domain (e.g., 'google' from 'google.co.in')
        base_domain = domain.split('.')[0]
        
        # Check if this base domain exists in our patterns
        if base_domain in self.trusted_domain_patterns:
            # Check domain against all variants (with and without www)
            domain_matches = False
            for trusted_variant in self.trusted_domain_patterns[base_domain]:
                if domain == trusted_variant or domain == re.sub(r'^www\.', '', trusted_variant):
                    domain_matches = True
                    break
            
            if not domain_matches:
                score -= 50
                reasons.append(f"Suspicious: Uses trusted brand name '{base_domain}' with unofficial TLD")
            else:
                reasons.append("Trusted domain variant")
                score += 10
        else:
            # Check for similarity with known base domains
            highest_similarity = 0
            similar_to = None
            
            for trusted_base in self.trusted_domain_patterns.keys():
                similarity = fuzz.ratio(base_domain, trusted_base)
                if similarity > highest_similarity:
                    highest_similarity = similarity
                    similar_to = trusted_base

            if highest_similarity > 85 and base_domain != similar_to:
                score -= 50
                reasons.append(f"Very similar to trusted brand name: {similar_to}")
            elif highest_similarity > 75 and base_domain != similar_to:
                score -= 30
                reasons.append(f"Somewhat similar to trusted brand name: {similar_to}")

        return {"score": score, "reasons": reasons}

    def check_ssl_cert(self, url: str) -> Dict:
        score = 0
        reasons = []
        
        if not url.startswith('https://'):
            score -= 20
            reasons.append("No SSL/TLS encryption")
            return {"score": score, "reasons": reasons}
        
        try:
            domain = urlparse(url).netloc.split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if datetime.now() > not_after:
                        score -= 30
                        reasons.append("SSL certificate has expired")
                    else:
                        reasons.append("Valid SSL certificate")
                    
                    # Check certificate domain match
                    if 'subjectAltName' in cert:
                        names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                        if domain not in names:
                            if not any(domain.endswith('.' + name[2:]) for name in names if name.startswith('*.')):
                                score -= 30
                                reasons.append("Domain name doesn't match certificate")
                            else:
                                reasons.append("Domain matches wildcard certificate")
                        else:
                            reasons.append("Domain matches certificate")
                    
        except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
            score -= 20
            reasons.append(f"SSL certificate check failed: {str(e)}")
        except Exception as e:
            score -= 10
            reasons.append(f"Error checking SSL certificate: {str(e)}")

        return {"score": score, "reasons": reasons}

    def check_url_shortener(self, url: str) -> Dict:
        score = 0
        reasons = []
        
        domain = urlparse(url).netloc.lower()
        if domain in self.url_shorteners:
            score -= 10
            reasons.append("URL uses a URL shortening service")
        
        return {"score": score, "reasons": reasons}