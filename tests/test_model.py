"""
Unit tests for the URL detection model
"""

import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.model import URLDetector, makeTokens
from backend.utils import extract_features, is_valid_url

class TestURLDetector(unittest.TestCase):
    
    def setUp(self):
        self.detector = URLDetector()
        
    def test_makeTokens(self):
        """Test the tokenizer function"""
        url = "https://www.example.com/path/to/page"
        tokens = makeTokens(url)
        
        self.assertIsInstance(tokens, list)
        self.assertIn('example', tokens)
        self.assertNotIn('com', tokens)  # com should be removed
        
    def test_extract_features(self):
        """Test feature extraction"""
        url = "https://www.example-test.com/path123"
        features = extract_features(url)
        
        self.assertEqual(features['has_https'], 1)
        self.assertEqual(features['has_www'], 1)
        self.assertEqual(features['hyphen_count'], 1)
        self.assertEqual(features['digit_count'], 3)
        
    def test_is_valid_url(self):
        """Test URL validation"""
        self.assertTrue(is_valid_url("https://google.com"))
        self.assertTrue(is_valid_url("http://192.168.1.1"))
        self.assertTrue(is_valid_url("example.com"))
        self.assertFalse(is_valid_url("not-a-url"))
        
    def test_model_prediction(self):
        """Test that model can make predictions"""
        # Test with a known safe URL
        result = self.detector.predict("https://google.com")
        
        self.assertIn('prediction', result)
        self.assertIn('confidence', result)
        self.assertIn('probabilities', result)
        
        # Check that probabilities sum to approximately 1
        prob_sum = sum(result['probabilities'].values())
        self.assertAlmostEqual(prob_sum, 1.0, places=2)

class TestUtils(unittest.TestCase):
    
    def test_extract_domain(self):
        from backend.utils import extract_domain
        
        self.assertEqual(extract_domain("https://example.com/path"), "example.com")
        self.assertEqual(extract_domain("http://sub.example.com:8080/path"), "sub.example.com")
        
    def test_clean_url(self):
        from backend.utils import clean_url
        
        self.assertEqual(clean_url("example.com"), "http://example.com")
        self.assertEqual(clean_url("HTTPS://EXAMPLE.COM/"), "https://example.com")

if __name__ == '__main__':
    unittest.main()