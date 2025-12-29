import pickle
import pandas as pd
import numpy as np
import socket
import json
import urllib.request
import re
import os
import warnings
warnings.filterwarnings('ignore')

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

# Known legitimate domains (whitelist for safety)
LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'reddit.com',
    'amazon.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
    'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com', 'medium.com',
    'cloudflare.com', 'adobe.com', 'wordpress.com', 'tumblr.com', 'pinterest.com',
    'paypal.com', 'ebay.com', 'cnn.com', 'bbc.com', 'nytimes.com'
}

def extract_domain(url):
    """Extract domain from URL"""
    try:
        url = str(url).lower()
        if '://' in url:
            domain = url.split('://')[1].split('/')[0]
        else:
            domain = url.split('/')[0]
        domain = domain.split(':')[0]
        return domain
    except:
        return ''

def has_phishing_indicators(url):
    """Check for common phishing URL indicators"""
    url_str = str(url).lower()
    domain = extract_domain(url)
    
    indicators = 0
    
    # Suspicious keywords in URL
    phishing_keywords = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'password', 'banking', 'suspended', 'locked',
        'credential', 'wallet', 'payment', 'billing', 'security',
        'validation', 'authorization'
    ]
    for keyword in phishing_keywords:
        if keyword in url_str:
            indicators += 1
    
    # Brand impersonation patterns (brand name followed by suspicious words)
    brands = ['paypal', 'amazon', 'netflix', 'facebook', 'google', 
              'microsoft', 'apple', 'bank', 'secure', 'verify']
    for brand in brands:
        if brand in url_str:
            # Check if it's actually the legitimate domain
            if not domain.endswith(f'{brand}.com') and not domain.endswith(f'{brand}.org'):
                indicators += 2  # Strong indicator
    
    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.work', '.click', '.link', '.pw', '.tk']
    for tld in suspicious_tlds:
        if url_str.endswith(tld) or tld in url_str:
            indicators += 2
    
    # IP address in URL
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        indicators += 1
    
    # Many hyphens in domain (common in phishing)
    if domain.count('-') > 2:
        indicators += 1
    
    # Very long domain
    if len(domain) > 40:
        indicators += 1
    
    # @ symbol in URL (used to hide real domain)
    if '@' in url_str:
        indicators += 3
    
    return indicators

def is_legitimate_domain(url):
    """Check if URL is from a known legitimate domain"""
    domain = extract_domain(url)
    for legit in LEGITIMATE_DOMAINS:
        if domain.endswith(legit):
            return True
    return False

# Enhanced tokenizer with better URL parsing
def makeTokens(url):
    """Enhanced tokenizer for URL analysis"""
    try:
        url = str(url).lower()
        tokens = []
        
        # Extract domain separately
        domain = extract_domain(url)
        if domain:
            tokens.append(f"domain_{domain}")
            # Add TLD
            if '.' in domain:
                tld = domain.split('.')[-1]
                tokens.append(f"tld_{tld}")
        
        # Split by multiple delimiters
        delimiters = ['/', '.', '-', '_', '?', '=', '&', '%', ':', '@', '+', '~']
        parts = [url]
        
        for delim in delimiters:
            new_parts = []
            for part in parts:
                new_parts.extend(part.split(delim))
            parts = new_parts
        
        # Filter and add tokens
        for token in parts:
            token = token.strip()
            if len(token) >= 2 and not token.isdigit():
                if token not in {'http', 'https', 'www'}:
                    tokens.append(token)
        
        # Add structural features as tokens
        tokens.append(f"len_{min(len(url)//20, 10)}")
        tokens.append(f"dots_{min(url.count('.'), 10)}")
        tokens.append(f"slashes_{min(url.count('/'), 10)}")
        tokens.append(f"hyphens_{min(url.count('-'), 10)}")
        
        # Suspicious keyword features
        suspicious_words = ['login', 'signin', 'verify', 'account', 'secure', 'update',
                          'confirm', 'password', 'banking', 'suspended', 'locked']
        for word in suspicious_words:
            if word in url:
                tokens.append(f"suspicious_{word}")
        
        # Protocol
        if url.startswith('https'):
            tokens.append('proto_https')
        elif url.startswith('http'):
            tokens.append('proto_http')
        
        return tokens
    except:
        return []

class URLDetector:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self.label_encoder = None
        self.load_model()
    
    def load_model(self):
        """Load or train the model"""
        model_files = ['model.pkl', 'vectorizer.pkl', 'label_encoder.pkl']
        
        if all(os.path.exists(f) for f in model_files):
            print("Loading existing model...")
            with open('model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            with open('vectorizer.pkl', 'rb') as f:
                self.vectorizer = pickle.load(f)
            with open('label_encoder.pkl', 'rb') as f:
                self.label_encoder = pickle.load(f)
            print("Model loaded successfully!")
        else:
            print("No existing model found. Training new model...")
            self.train_model()
    
    def train_model(self):
        """Train the model with improved approach"""
        try:
            print("Loading dataset...")
            
            # Try multiple paths
            possible_paths = [
                "data/malicious_phish.csv",
                "../data/malicious_phish.csv",
                "malicious_phish.csv"
            ]
            
            df = None
            for path in possible_paths:
                if os.path.exists(path):
                    print(f"Loading from: {path}")
                    df = pd.read_csv(path)
                    break
            
            if df is None:
                raise FileNotFoundError("Could not find dataset file")
            
            print(f"Loaded {len(df)} URLs")
            
            # Prepare data
            if 'type' in df.columns:
                df = df.rename(columns={'type': 'label'})
            elif len(df.columns) == 2:
                df.columns = ['url', 'label']
            
            # Clean data
            df = df.dropna()
            df['url'] = df['url'].astype(str)
            df['label'] = df['label'].astype(str).str.lower().str.strip()
            
            print(f"\nOriginal class distribution:")
            print(df['label'].value_counts())
            
            # CRITICAL: Add synthetic examples of common legitimate sites
            print("\nAdding legitimate domain examples...")
            legitimate_examples = []
            
            for domain in LEGITIMATE_DOMAINS:
                # Add various URL patterns for each domain
                patterns = [
                    f"https://www.{domain}",
                    f"https://{domain}",
                    f"https://www.{domain}/page",
                    f"https://{domain}/search?q=test",
                    f"https://www.{domain}/user/profile",
                    f"https://{domain}/about",
                ]
                for pattern in patterns:
                    legitimate_examples.append({'url': pattern, 'label': 'benign'})
            
            legit_df = pd.DataFrame(legitimate_examples)
            print(f"Added {len(legit_df)} legitimate domain examples")
            
            # Combine with original data
            df = pd.concat([df, legit_df], ignore_index=True)
            
            # Enhanced balancing strategy
            print("\nBalancing dataset with better strategy...")
            
            # Sample sizes - keep benign larger to learn legitimate patterns
            sample_sizes = {
                'benign': 80000,  # Significantly more benign to learn legitimate patterns
                'phishing': 40000,
                'malware': 40000,
                'defacement': 40000
            }
            
            balanced_dfs = []
            for label, size in sample_sizes.items():
                if label in df['label'].values:
                    label_data = df[df['label'] == label]
                    sample_size = min(size, len(label_data))
                    balanced_dfs.append(label_data.sample(sample_size, random_state=42))
            
            df = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
            print(f"After balancing: {len(df)} URLs")
            print(df['label'].value_counts())
            
            # Extract URLs and labels
            urls = df['url'].tolist()
            
            # Encode labels
            self.label_encoder = LabelEncoder()
            y = self.label_encoder.fit_transform(df['label'])
            print(f"\nEncoded classes: {self.label_encoder.classes_}")
            
            # Create TF-IDF features
            print("\nCreating TF-IDF features...")
            self.vectorizer = TfidfVectorizer(
                tokenizer=makeTokens,
                max_features=8000,  # More features for better distinction
                ngram_range=(1, 3),
                min_df=2,
                max_df=0.8,
                sublinear_tf=True
            )
            X_tfidf = self.vectorizer.fit_transform(urls)
            print(f"TF-IDF matrix shape: {X_tfidf.shape}")
            
            # Split data BEFORE SMOTE
            X_train, X_test, y_train, y_test = train_test_split(
                X_tfidf, y, test_size=0.2, random_state=42, stratify=y
            )
            print(f"\nTraining samples: {X_train.shape[0]}")
            print(f"Test samples: {X_test.shape[0]}")
            
            # Class distribution before SMOTE
            unique, counts = np.unique(y_train, return_counts=True)
            print(f"\nTraining set class distribution before SMOTE:")
            for cls, count in zip(unique, counts):
                print(f"  {self.label_encoder.classes_[cls]}: {count}")
            
            # Apply SMOTE with adjusted sampling
            print("\nApplying SMOTE...")
            # Use sampling strategy to not oversample benign too much
            sampling_strategy = {
                0: int(counts[unique == 0][0] * 1.0),  # benign - keep as is (or adjust index)
                1: int(counts[unique == 0][0] * 0.8),  # others - balance but less than benign
                2: int(counts[unique == 0][0] * 0.8),
                3: int(counts[unique == 0][0] * 0.8),
            }
            
            # Find benign class index
            benign_idx = list(self.label_encoder.classes_).index('benign')
            benign_count = counts[unique == benign_idx][0]
            
            # Adjust strategy
            sampling_strategy = {}
            for cls in unique:
                if cls == benign_idx:
                    sampling_strategy[cls] = benign_count
                else:
                    sampling_strategy[cls] = int(benign_count * 0.7)
            
            smote = SMOTE(random_state=42, k_neighbors=5, sampling_strategy=sampling_strategy)
            X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
            
            unique, counts = np.unique(y_train_bal, return_counts=True)
            print(f"After SMOTE - Training samples: {X_train_bal.shape[0]}")
            for cls, count in zip(unique, counts):
                print(f"  {self.label_encoder.classes_[cls]}: {count}")
            
            # Train Random Forest
            print("\nTraining Random Forest model...")
            self.model = RandomForestClassifier(
                n_estimators=300,  # More trees
                max_depth=25,  # Deeper trees
                min_samples_split=8,
                min_samples_leaf=3,
                max_features='sqrt',
                class_weight='balanced',
                random_state=42,
                n_jobs=-1,
                verbose=0
            )
            self.model.fit(X_train_bal, y_train_bal)
            
            # Evaluate on test set
            print("\nEvaluating on held-out test set...")
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average='weighted')
            
            print(f"\nTest Set Performance:")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"F1 Score: {f1:.4f}")
            
            print("\nClassification Report (Test Set):")
            print(classification_report(y_test, y_pred, 
                                       target_names=self.label_encoder.classes_,
                                       digits=4))
            
            # Per-class accuracy
            print("\nPer-class accuracy on test set:")
            for i, class_name in enumerate(self.label_encoder.classes_):
                class_mask = y_test == i
                if class_mask.sum() > 0:
                    class_acc = accuracy_score(y_test[class_mask], y_pred[class_mask])
                    print(f"  {class_name}: {class_acc:.4f} ({class_mask.sum()} samples)")
            
            # Save model
            print("\nSaving model...")
            with open('model.pkl', 'wb') as f:
                pickle.dump(self.model, f)
            with open('vectorizer.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)
            with open('label_encoder.pkl', 'wb') as f:
                pickle.dump(self.label_encoder, f)
            
            print("Model saved successfully!")
            
        except Exception as e:
            print(f"Error training model: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    def predict(self, url):
        """Predict URL category with whitelist check and phishing heuristics"""
        if self.model is None or self.vectorizer is None:
            self.load_model()
        
        try:
            url_str = str(url).lower().strip()
            
            # CRITICAL: Check whitelist first
            if is_legitimate_domain(url_str):
                # Known legitimate domain - high confidence benign
                return {
                    'prediction': 'benign',
                    'confidence': 0.95,
                    'probabilities': {
                        'benign': 0.95,
                        'phishing': 0.02,
                        'malware': 0.02,
                        'defacement': 0.01
                    },
                    'is_malicious': False,
                    'whitelist_match': True
                }
            
            # Check phishing indicators
            phishing_score = has_phishing_indicators(url_str)
            
            # Transform URL
            url_vector = self.vectorizer.transform([url_str])
            
            # Get predictions
            prediction_idx = self.model.predict(url_vector)[0]
            prediction_proba = self.model.predict_proba(url_vector)[0]
            
            # Get prediction and confidence
            prediction = self.label_encoder.classes_[prediction_idx]
            confidence = float(prediction_proba[prediction_idx])
            
            # Get all probabilities
            probabilities = {}
            for i, class_name in enumerate(self.label_encoder.classes_):
                probabilities[class_name] = float(prediction_proba[i])
            
            # Enhanced confidence thresholding with better logic
            benign_prob = probabilities.get('benign', 0)
            phishing_prob = probabilities.get('phishing', 0)
            malware_prob = probabilities.get('malware', 0)
            defacement_prob = probabilities.get('defacement', 0)
            
            # Get max malicious probability
            max_malicious_prob = max(phishing_prob, malware_prob, defacement_prob)
            
            # Check for suspicious patterns
            suspicious_keywords = ['login', 'signin', 'verify', 'account', 
                                  'secure', 'update', 'confirm', 'password',
                                  'suspended', 'locked', 'banking', 'credential',
                                  'wallet', 'payment']
            has_suspicious = any(word in url_str for word in suspicious_keywords)
            
            # Strong override: If many phishing indicators, classify as phishing
            if phishing_score >= 3:
                if phishing_prob > 0.15 or max_malicious_prob > benign_prob:
                    prediction = 'phishing'
                    confidence = max(phishing_prob, 0.6)
            
            # If benign prediction but has suspicious keywords and phishing probability is significant
            elif prediction == 'benign' and has_suspicious:
                if phishing_prob > 0.2:  # Lower threshold for suspicious URLs
                    prediction = 'phishing'
                    confidence = phishing_prob
            
            # Only mark as uncertain if truly ambiguous (very close probabilities)
            # Don't be overly cautious - trust the model more
            elif prediction != 'benign':
                # Only mark uncertain if benign is VERY close to the malicious prediction
                prob_diff = confidence - benign_prob
                if prob_diff < 0.15 and confidence < 0.5:  # Very tight threshold
                    prediction = 'uncertain'
                    confidence = max(prediction_proba)
            
            # Additional check: if multiple malicious types agree, trust them
            if prediction != 'benign':
                if max_malicious_prob > benign_prob:
                    # Malicious predictions outweigh benign - don't mark uncertain
                    if prediction == 'uncertain':
                        # Find the highest malicious class
                        malicious_classes = {
                            'phishing': phishing_prob,
                            'malware': malware_prob,
                            'defacement': defacement_prob
                        }
                        prediction = max(malicious_classes.items(), key=lambda x: x[1])[0]
                        confidence = max_malicious_prob
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'probabilities': probabilities,
                'is_malicious': prediction not in ['benign', 'uncertain'],
                'whitelist_match': False,
                'phishing_indicators': phishing_score if phishing_score > 0 else None
            }
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'probabilities': {},
                'is_malicious': False,
                'error': str(e)
            }

# Global detector
detector = URLDetector()

def predict_url(url):
    """Predict a single URL"""
    return detector.predict(url)

def retrain_model():
    """Retrain the model"""
    detector.train_model()
    return {"status": "Model retrained successfully"}

def get_url_info(url):
    """Get URL information"""
    try:
        if '://' in url:
            domain = url.split('://')[1].split('/')[0]
        else:
            domain = url.split('/')[0]
        
        domain = domain.split(':')[0]
        ip = socket.gethostbyname(domain)
        
        api_url = f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp'
        response = urllib.request.urlopen(api_url)
        data = json.loads(response.read())
        
        if data.get('status') == 'success':
            return {
                'ip': ip,
                'country': data.get('country', ''),
                'region': data.get('regionName', ''),
                'city': data.get('city', ''),
                'isp': data.get('isp', '')
            }
        else:
            return {'ip': ip, 'error': 'API error'}
            
    except Exception as e:
        return {'error': str(e)}

def get_threat_description(threat_type):
    """Get threat description"""
    descriptions = {
        'benign': 'Safe website with no known threats',
        'defacement': 'Website that has been hacked and modified',
        'phishing': 'Fraudulent site attempting to steal credentials',
        'malware': 'Site distributing malicious software',
        'uncertain': 'Unable to classify with high confidence',
        'unknown': 'Unable to classify'
    }
    return descriptions.get(threat_type, 'Unknown threat type')

def get_recommendation(threat_type):
    """Get recommendation"""
    recommendations = {
        'benign': 'This site appears safe. Proceed normally.',
        'defacement': 'Warning: Site appears compromised. Avoid visiting.',
        'phishing': 'Critical: This is a phishing site. Do not enter any personal information.',
        'malware': 'Critical: Site contains malware. Do not download anything.',
        'uncertain': 'Exercise caution. Unable to verify site safety with high confidence.',
        'unknown': 'Exercise caution. Unable to verify site safety.'
    }
    return recommendations.get(threat_type, 'Proceed with caution.')