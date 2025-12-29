"""
Quick test script to verify model improvements without full retraining
"""
import sys
import os

# Add parent directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from model import URLDetector

def test_urls():
    print("=" * 70)
    print("QUICK URL DETECTION TEST")
    print("=" * 70)
    
    detector = URLDetector()
    
    # Test cases
    test_cases = [
        # Legitimate URLs (should be benign)
        ("https://www.google.com", "benign", "Legitimate - Google"),
        ("https://github.com/user/repo", "benign", "Legitimate - GitHub"),
        ("https://www.amazon.com/product", "benign", "Legitimate - Amazon"),
        ("https://stackoverflow.com/questions", "benign", "Legitimate - StackOverflow"),
        
        # Obvious phishing URLs
        ("http://paypal-secure-login-verify.com/signin", "phishing", "Phishing - PayPal fake"),
        ("https://amazon-account-suspended.xyz/verify", "phishing", "Phishing - Amazon fake"),
        ("http://secure-banking-update.net/login", "phishing", "Phishing - Banking fake"),
        ("https://netflix-payment-failed.com/update", "phishing", "Phishing - Netflix fake"),
        ("http://apple-verify-account.tk/signin", "phishing", "Phishing - Apple fake (.tk TLD)"),
        
        # Malware-like
        ("http://192.168.1.1/admin/login.php", "malware", "Suspicious - IP address"),
        
        # Edge cases
        ("https://legitimate-company.com", "benign", "Generic legitimate"),
        ("http://suspicious-verify-account-now.xyz", "phishing", "Suspicious domain + TLD"),
    ]
    
    print("\nTesting URLs...\n")
    print("-" * 70)
    
    correct = 0
    total = len(test_cases)
    
    for url, expected, description in test_cases:
        result = detector.predict(url)
        prediction = result['prediction']
        confidence = result['confidence']
        
        # Consider 'uncertain' leaning toward malicious as acceptable for phishing
        is_correct = (prediction == expected) or \
                    (expected == 'phishing' and prediction in ['phishing', 'malware', 'uncertain'])
        
        if is_correct:
            correct += 1
            symbol = "✓"
            color = ""
        else:
            symbol = "✗"
            color = ""
        
        print(f"{symbol} {description}")
        print(f"  URL: {url[:60]}...")
        print(f"  Expected: {expected:12} | Got: {prediction:12} (conf: {confidence:.2%})")
        
        # Show phishing indicators if present
        if 'phishing_indicators' in result and result['phishing_indicators']:
            print(f"  Phishing indicators: {result['phishing_indicators']}")
        
        # Show top probabilities for incorrect predictions
        if not is_correct and 'probabilities' in result:
            sorted_probs = sorted(result['probabilities'].items(), 
                                key=lambda x: x[1], reverse=True)[:3]
            print(f"  Probabilities: {sorted_probs}")
        
        print()
    
    print("-" * 70)
    print(f"\nAccuracy: {correct}/{total} ({correct/total*100:.1f}%)")
    print("=" * 70)
    
    # Specific metrics
    print("\nCategory Performance:")
    
    legitimate_correct = sum(1 for url, expected, desc in test_cases[:4] 
                           if detector.predict(url)['prediction'] == 'benign')
    print(f"  Legitimate URLs: {legitimate_correct}/4 ({legitimate_correct/4*100:.0f}%)")
    
    phishing_detected = sum(1 for url, expected, desc in test_cases[4:9]
                           if detector.predict(url)['prediction'] in ['phishing', 'malware', 'uncertain'])
    print(f"  Phishing Detection: {phishing_detected}/5 ({phishing_detected/5*100:.0f}%)")
    
    print("\n" + "=" * 70)

if __name__ == '__main__':
    test_urls()