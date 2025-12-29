"""
Utility functions for the URL detection system
"""

import re
import hashlib
import socket
import json
import urllib.request
from urllib.parse import urlparse
import tldextract
import ipaddress
import pandas as pd
import numpy as np
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_domain(url):
    """
    Extract domain from URL using tldextract for better accuracy
    
    Args:
        url (str): The URL to parse
        
    Returns:
        str: Extracted domain
    """
    try:
        # Use tldextract for better domain extraction
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # If subdomain exists and is meaningful, include it
        if extracted.subdomain and extracted.subdomain not in ['www', 'ww2', 'web']:
            domain = f"{extracted.subdomain}.{domain}"
            
        return domain.lower()
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {e}")
        # Fallback to urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.split(':')[0]
            return domain.lower()
        except:
            return url.lower()

def extract_features(url):
    """
    Extract comprehensive features from URL for enhanced analysis
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of extracted features
    """
    features = {}
    
    try:
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(extract_domain(url))
        
        # Character counts
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['equals_count'] = url.count('=')
        features['question_mark_count'] = url.count('?')
        features['ampersand_count'] = url.count('&')
        features['at_count'] = url.count('@')
        features['exclamation_count'] = url.count('!')
        
        # Character type counts
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        features['special_char_count'] = sum(not c.isalnum() for c in url)
        
        # Ratios
        if features['url_length'] > 0:
            features['digit_ratio'] = features['digit_count'] / features['url_length']
            features['letter_ratio'] = features['letter_count'] / features['url_length']
            features['special_char_ratio'] = features['special_char_count'] / features['url_length']
        else:
            features['digit_ratio'] = 0
            features['letter_ratio'] = 0
            features['special_char_ratio'] = 0
        
        # Protocol features
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['has_http'] = 1 if url.startswith('http://') else 0
        features['has_ftp'] = 1 if url.startswith('ftp://') else 0
        features['has_www'] = 1 if 'www.' in url.lower() else 0
        
        # Suspicious patterns
        features['has_port'] = 1 if re.search(r':\d+', url) else 0
        features['has_ip'] = 1 if is_ip_address(url) else 0
        features['has_hex'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        features['has_binary'] = 1 if re.search(r'%u[0-9a-fA-F]{4}', url) else 0
        
        # Keyword checks (common in malicious URLs)
        suspicious_keywords = ['login', 'secure', 'account', 'bank', 'verify', 'update', 
                              'confirm', 'webscr', 'phishing', 'malware', 'virus', 'trojan',
                              'free', 'download', 'install', 'exe', 'rar', 'zip', 'crack',
                              'paypal', 'ebay', 'amazon', 'facebook', 'google', 'apple']
        
        for keyword in suspicious_keywords:
            features[f'has_{keyword}'] = 1 if keyword in url.lower() else 0
        
        # Domain features
        domain = extract_domain(url)
        features['subdomain_count'] = domain.count('.')
        features['is_short_domain'] = 1 if len(domain) < 10 else 0
        features['is_long_domain'] = 1 if len(domain) > 30 else 0
        
        # Path features
        parsed = urlparse(url)
        path = parsed.path
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/') if path else 0
        features['has_file_extension'] = 1 if '.' in path.split('/')[-1] else 0
        
        # Query features
        query = parsed.query
        features['has_query'] = 1 if query else 0
        features['query_length'] = len(query)
        features['param_count'] = query.count('&') + 1 if query else 0
        
        # Entropy calculation (higher entropy = more random = potentially suspicious)
        features['entropy'] = calculate_entropy(url)
        
    except Exception as e:
        logger.error(f"Error extracting features from {url}: {e}")
        # Set default values for all features
        for key in features.keys():
            features[key] = 0
    
    return features

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string
    
    Args:
        text (str): Input string
        
    Returns:
        float: Entropy value
    """
    if not text:
        return 0.0
    
    # Get frequency of each character
    freq_dict = {}
    for char in text:
        freq_dict[char] = freq_dict.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_len = len(text)
    
    for freq in freq_dict.values():
        probability = freq / text_len
        entropy -= probability * (probability and np.log2(probability))
    
    return entropy

def is_ip_address(url):
    """
    Check if URL contains an IP address
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if contains IP address
    """
    try:
        # Extract domain
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain = domain.split(':')[0]
        
        # Check if domain is an IP address
        ipaddress.ip_address(domain)
        return True
    except:
        # Check for IP patterns in the entire URL
        ip_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            r'\[[0-9a-fA-F:]+\]'  # IPv6
        ]
        
        for pattern in ip_patterns:
            if re.search(pattern, url):
                return True
        
        return False

def calculate_url_hash(url):
    """
    Calculate hash of URL for deduplication
    
    Args:
        url (str): URL to hash
        
    Returns:
        str: MD5 hash of the URL
    """
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def is_valid_url(url):
    """
    Validate URL format
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid URL format
    """
    # Basic URL pattern
    pattern = re.compile(
        r'^(https?|ftp)://'  # Protocol
        r'(([A-Z0-9]([A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # Domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
        r'(?::\d+)?'  # Optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(re.match(pattern, url))

def clean_url(url):
    """
    Clean and normalize URL
    
    Args:
        url (str): URL to clean
        
    Returns:
        str: Cleaned URL
    """
    if not url or not isinstance(url, str):
        return ""
    
    url = url.strip()
    
    # Remove whitespace and control characters
    url = re.sub(r'[\s\x00-\x1f\x7f]+', '', url)
    
    # Convert to lowercase
    url = url.lower()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url
    
    # Ensure proper URL format
    parsed = urlparse(url)
    
    # Reconstruct URL with proper components
    cleaned_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    if parsed.params:
        cleaned_url += f";{parsed.params}"
    if parsed.query:
        cleaned_url += f"?{parsed.query}"
    if parsed.fragment:
        cleaned_url += f"#{parsed.fragment}"
    
    # Remove trailing slashes from path (except root)
    if cleaned_url.endswith('/') and len(parsed.path) > 1:
        cleaned_url = cleaned_url.rstrip('/')
    
    return cleaned_url

def get_ip_info(ip_address):
    """
    Get information about an IP address
    
    Args:
        ip_address (str): IP address to look up
        
    Returns:
        dict: IP information
    """
    try:
        api_url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        
        response = urllib.request.urlopen(api_url, timeout=5)
        data = json.loads(response.read())
        
        if data.get('status') == 'success':
            return {
                'ip': data.get('query', ip_address),
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', ''),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'zip': data.get('zip', ''),
                'latitude': data.get('lat', 0),
                'longitude': data.get('lon', 0),
                'timezone': data.get('timezone', ''),
                'isp': data.get('isp', 'Unknown'),
                'organization': data.get('org', ''),
                'as_number': data.get('as', ''),
                'success': True
            }
        else:
            return {
                'ip': ip_address,
                'error': data.get('message', 'API error'),
                'success': False
            }
    except Exception as e:
        logger.error(f"Error getting IP info for {ip_address}: {e}")
        return {
            'ip': ip_address,
            'error': str(e),
            'success': False
        }

def resolve_domain_to_ip(domain):
    """
    Resolve domain name to IP address
    
    Args:
        domain (str): Domain name
        
    Returns:
        str: IP address or empty string if resolution fails
    """
    try:
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Resolve domain
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        logger.warning(f"Could not resolve domain: {domain}")
        return ""
    except Exception as e:
        logger.error(f"Error resolving domain {domain}: {e}")
        return ""

def generate_report(prediction_data, url_info=None):
    """
    Generate a comprehensive report from prediction data
    
    Args:
        prediction_data (dict): Prediction results
        url_info (dict, optional): Additional URL information
        
    Returns:
        dict: Complete report
    """
    report = {
        'timestamp': datetime.now().isoformat(),
        'url': prediction_data.get('url', ''),
        'prediction': prediction_data.get('prediction', 'unknown'),
        'confidence': prediction_data.get('confidence', 0.0),
        'probabilities': prediction_data.get('probabilities', {}),
        'severity': prediction_data.get('severity', 'unknown'),
        'description': prediction_data.get('description', ''),
        'recommendation': prediction_data.get('recommendation', '')
    }
    
    if url_info:
        report['url_info'] = url_info
    
    # Calculate risk score
    risk_scores = {
        'benign': 0,
        'defacement': 40,
        'phishing': 70,
        'malware': 90,
        'unknown': 50
    }
    
    prediction = prediction_data.get('prediction', 'unknown').lower()
    base_score = risk_scores.get(prediction, 50)
    confidence = prediction_data.get('confidence', 0.5)
    
    # Adjust score based on confidence
    risk_score = base_score + (confidence * 10)
    report['risk_score'] = min(100, max(0, int(risk_score)))
    
    # Add risk level
    if report['risk_score'] >= 80:
        report['risk_level'] = 'Critical'
    elif report['risk_score'] >= 60:
        report['risk_level'] = 'High'
    elif report['risk_score'] >= 40:
        report['risk_level'] = 'Medium'
    elif report['risk_score'] >= 20:
        report['risk_level'] = 'Low'
    else:
        report['risk_level'] = 'Very Low'
    
    return report

def save_results_to_csv(results, filename='url_scan_results.csv'):
    """
    Save scan results to CSV file
    
    Args:
        results (list): List of scan results
        filename (str): Output filename
        
    Returns:
        bool: True if successful
    """
    try:
        if not results:
            logger.warning("No results to save")
            return False
        
        # Convert results to DataFrame
        df = pd.DataFrame(results)
        
        # Save to CSV
        df.to_csv(filename, index=False)
        logger.info(f"Results saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving results to CSV: {e}")
        return False

def load_urls_from_file(filename, limit=None):
    """
    Load URLs from a file
    
    Args:
        filename (str): File containing URLs
        limit (int, optional): Maximum number of URLs to load
        
    Returns:
        list: List of URLs
    """
    urls = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # Skip empty lines and comments
                    urls.append(url)
                
                if limit and len(urls) >= limit:
                    break
        
        logger.info(f"Loaded {len(urls)} URLs from {filename}")
        return urls
    except Exception as e:
        logger.error(f"Error loading URLs from {filename}: {e}")
        return []

def validate_and_clean_urls(urls):
    """
    Validate and clean a list of URLs
    
    Args:
        urls (list): List of URLs to validate
        
    Returns:
        tuple: (valid_urls, invalid_urls)
    """
    valid_urls = []
    invalid_urls = []
    
    for url in urls:
        cleaned_url = clean_url(url)
        if is_valid_url(cleaned_url):
            valid_urls.append(cleaned_url)
        else:
            invalid_urls.append(url)
    
    return valid_urls, invalid_urls