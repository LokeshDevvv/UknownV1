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

load_dotenv()

class PhishingDetector:
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self._vt_client = None
        
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

    async def analyze_url(self, url: str) -> Dict:
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Initialize features dictionary
            features = {
                'is_safe': True,
                'warnings': [],
                'vendor_alerts': []
            }
            
            # Check if it's a trusted educational domain
            is_edu_domain = any(edu_domain in domain for edu_domain in self.trusted_edu_domains)
            domain_tld = domain.split('.')[-2:] if len(domain.split('.')) > 1 else []
            is_edu_tld = '.'.join(domain_tld) in self.trusted_tlds
            
            # Check if it's a known trusted domain
            is_trusted_domain = domain in self.trusted_domains or any(domain.endswith('.' + td) for td in self.trusted_domains)
            
            if is_edu_domain or is_edu_tld:
                features['warnings'].append('✅ This is a verified educational website')
            elif is_trusted_domain:
                features['warnings'].append('✅ This is a verified trusted website')
            
            # Check SSL certificate
            if parsed_url.scheme == 'https':
                features['warnings'].append('✅ Connection is secure (HTTPS)')
            else:
                features['warnings'].append('⚠️ Connection is not secure (No HTTPS)')
                features['is_safe'] = False
            
            # Get URL structure analysis
            url_structure = self.check_url_structure(url)
            if url_structure['score'] > 0:
                features['is_safe'] = False
                features['warnings'].extend(url_structure['reasons'])
            
            # Get security vendor analysis
            vendor_analysis = await self.check_security_vendors(url)
            if vendor_analysis['score'] > 0:
                features['is_safe'] = False
                features['warnings'].extend(vendor_analysis['reasons'])
                features['vendor_alerts'] = vendor_analysis.get('vendor_results', [])
            
            # Additional checks for high-risk combinations
            if not parsed_url.scheme == 'https' and not (is_edu_domain or is_edu_tld or is_trusted_domain):
                features['warnings'].append('⚠️ CRITICAL: Untrusted website without secure connection')
                features['is_safe'] = False
            
            # Prepare user-friendly response
            safety_status = "SAFE" if features['is_safe'] else "DANGEROUS"
            main_message = ""
            
            if features['is_safe']:
                if is_edu_domain or is_edu_tld:
                    main_message = "✅ This is a legitimate educational website"
                elif is_trusted_domain:
                    main_message = "✅ This is a legitimate trusted website"
                else:
                    main_message = "✅ This website appears to be safe"
            else:
                if len(features['vendor_alerts']) > 0:
                    main_message = "🚨 WARNING: Multiple security services have flagged this website as dangerous"
                else:
                    main_message = "⚠️ WARNING: This website shows suspicious characteristics"
            
            return {
                'url': url,
                'safety_status': safety_status,
                'main_message': main_message,
                'details': features['warnings'],
                'vendor_alerts': features['vendor_alerts'] if not features['is_safe'] else []
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
        score = 0
        reasons = []
        
        # Check URL length
        if len(url) > 150:
            score += 30
            reasons.append("⚠️ Unusually long URL")
        elif len(url) > 100:
            score += 20
            reasons.append("⚠️ Long URL")
        
        # Check for suspicious characters with higher penalties
        suspicious_chars = re.findall(r'[@~`!#$%^&*()+=\[\]{}|\\;"\'<>?]', url)
        if suspicious_chars:
            if len(suspicious_chars) > 3:
                score += 40
                reasons.append(f"⚠️ Contains many suspicious characters: {', '.join(set(suspicious_chars))}")
            else:
                score += 20
                reasons.append(f"⚠️ Contains suspicious characters: {', '.join(set(suspicious_chars))}")
        
        # Higher penalty for IP addresses
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 50
            reasons.append("⚠️ Contains IP address instead of domain name")
        
        # Check for excessive subdomains
        domain = urlparse(url).netloc
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 3:
            score += 30
            reasons.append("⚠️ Excessive number of subdomains")
        
        # Check for encoded characters
        if '%' in url:
            encoded_chars = re.findall(r'%[0-9A-Fa-f]{2}', url)
            if len(encoded_chars) > 3:
                score += 40
                reasons.append("⚠️ Contains multiple encoded characters")
            else:
                score += 20
                reasons.append("⚠️ Contains encoded characters")

        # Check for short URLs or tracking parameters
        if re.search(r'/(sc|tr|em|rd|go)/[a-zA-Z0-9]{1,3}(\?|$)', url):
            score += 40
            reasons.append("⚠️ Suspicious URL pattern - possible redirect or tracking link")
        
        # Check for unusual TLDs
        tld = domain.split('.')[-1].lower()
        unusual_tlds = {'ws', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'date', 'faith', 'review', 'stream'}
        if tld in unusual_tlds:
            score += 40
            reasons.append(f"⚠️ Suspicious TLD: .{tld}")
        
        if score == 0:
            reasons.append("✅ URL structure appears normal")

        return {"score": score, "reasons": reasons}

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