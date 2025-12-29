"""
Script to train the URL detection model with comprehensive evaluation
"""
import sys
import os
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("URL DETECTION MODEL TRAINING")
print("=" * 60)

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    print("\n1. Importing modules...")
    from model import URLDetector
    import pandas as pd
    import numpy as np
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    print("   ✓ All imports successful")
    
except Exception as e:
    print(f"   ✗ Import error: {e}")
    print("\nTrying to install missing packages...")
    os.system("pip install pandas numpy scikit-learn imbalanced-learn -q")
    
    try:
        from model import URLDetector
        import pandas as pd
        import numpy as np
        from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
        print("   ✓ Imports successful after installation")
    except Exception as e2:
        print(f"   ✗ Still failing: {e2}")
        exit(1)

def test_sample_urls(detector):
    """Test the model on known good and bad URLs"""
    print("\n" + "=" * 60)
    print("TESTING ON SAMPLE URLs")
    print("=" * 60)
    
    # Known safe URLs
    safe_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.amazon.com",
        "https://www.youtube.com",
        "https://www.microsoft.com",
        "https://stackoverflow.com",
        "https://www.reddit.com"
    ]
    
    # Suspicious/Phishing-like URLs (examples of patterns)
    suspicious_urls = [
        "http://paypal-secure-login-verify.com/signin",
        "https://amazon-account-suspended.xyz/verify",
        "http://secure-banking-update.net/login",
        "https://netflix-payment-failed.com/update",
        "http://192.168.1.1/admin/login.php"
    ]
    
    print("\nTesting SAFE URLs:")
    print("-" * 60)
    safe_correct = 0
    for url in safe_urls:
        result = detector.predict(url)
        is_correct = result['prediction'] == 'benign'
        safe_correct += is_correct
        
        symbol = "✓" if is_correct else "✗"
        print(f"{symbol} {url[:50]:<50}")
        print(f"   Prediction: {result['prediction']:12} (Confidence: {result['confidence']:.2%})")
        if result['prediction'] != 'benign':
            # Show why it might have been misclassified
            sorted_probs = sorted(result['probabilities'].items(), 
                                key=lambda x: x[1], reverse=True)
            print(f"   Top predictions: {sorted_probs[:3]}")
        print()
    
    print(f"\nSafe URL Accuracy: {safe_correct}/{len(safe_urls)} ({safe_correct/len(safe_urls)*100:.1f}%)")
    
    print("\n" + "-" * 60)
    print("Testing SUSPICIOUS URLs:")
    print("-" * 60)
    suspicious_correct = 0
    for url in suspicious_urls:
        result = detector.predict(url)
        is_correct = result['prediction'] != 'benign'
        suspicious_correct += is_correct
        
        symbol = "✓" if is_correct else "✗"
        print(f"{symbol} {url[:50]:<50}")
        print(f"   Prediction: {result['prediction']:12} (Confidence: {result['confidence']:.2%})")
        sorted_probs = sorted(result['probabilities'].items(), 
                            key=lambda x: x[1], reverse=True)
        print(f"   Top predictions: {sorted_probs[:3]}")
        print()
    
    print(f"\nSuspicious URL Detection: {suspicious_correct}/{len(suspicious_urls)} ({suspicious_correct/len(suspicious_urls)*100:.1f}%)")

def train_and_evaluate():
    print("\n2. Initializing detector (this will train the model)...")
    detector = URLDetector()
    
    print("\n3. Loading dataset for evaluation...")
    
    # Try multiple paths
    possible_paths = [
        "data/malicious_phish.csv",
        "../data/malicious_phish.csv",
        "malicious_phish.csv",
        os.path.join(parent_dir, "data", "malicious_phish.csv")
    ]
    
    urls_data = None
    for path in possible_paths:
        if os.path.exists(path):
            print(f"   Found dataset at: {path}")
            try:
                urls_data = pd.read_csv(path)
                print(f"   ✓ Successfully loaded from: {path}")
                break
            except Exception as e:
                print(f"   ✗ Error loading {path}: {e}")
                continue
    
    if urls_data is None:
        print("   ✗ ERROR: Could not find or load dataset")
        print("   Current directory:", os.getcwd())
        print("   Available files:", os.listdir('.'))
        if os.path.exists('data'):
            print("   Files in data/:", os.listdir('data'))
        
        # Still run sample tests
        test_sample_urls(detector)
        return
    
    print(f"\n4. Dataset loaded: {len(urls_data)} URLs")
    
    # Prepare data
    print("\n5. Preparing evaluation data...")
    if len(urls_data.columns) == 2:
        urls_data.columns = ['url', 'label']
    elif 'type' in urls_data.columns:
        urls_data = urls_data.rename(columns={'type': 'label'})
    
    # Clean labels
    urls_data['label'] = urls_data['label'].astype(str).str.lower().str.strip()
    
    print(f"   Columns: {urls_data.columns.tolist()}")
    print(f"   Classes: {urls_data['label'].unique()}")
    print(f"   Full dataset distribution:")
    print(urls_data['label'].value_counts())
    
    # Stratified sample for evaluation (different from training data)
    print(f"\n6. Creating stratified test sample...")
    test_samples = []
    samples_per_class = 500  # 500 samples per class for testing
    
    for label in urls_data['label'].unique():
        label_data = urls_data[urls_data['label'] == label]
        sample_size = min(samples_per_class, len(label_data))
        # Use different random state than training (42 was used in training)
        test_samples.append(label_data.sample(sample_size, random_state=99))
    
    test_sample = pd.concat(test_samples).sample(frac=1, random_state=99)
    
    print(f"   Test sample size: {len(test_sample)}")
    print(f"   Test sample distribution:")
    print(test_sample['label'].value_counts())
    
    # Predict and evaluate
    print(f"\n7. Making predictions on {len(test_sample)} samples...")
    predictions = []
    confidences = []
    true_labels = []
    
    for idx, (_, row) in enumerate(test_sample.iterrows()):
        result = detector.predict(row['url'])
        predictions.append(result['prediction'])
        confidences.append(result['confidence'])
        true_labels.append(row['label'])
        
        # Show progress every 100 samples
        if (idx + 1) % 100 == 0:
            print(f"   Processed {idx + 1}/{len(test_sample)} samples...")
    
    # Calculate metrics
    print(f"\n8. Evaluation Results:")
    print("=" * 60)
    
    # Overall accuracy
    accuracy = accuracy_score(true_labels, predictions)
    avg_confidence = np.mean(confidences)
    
    print(f"Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Average Confidence: {avg_confidence:.4f} ({avg_confidence*100:.2f}%)")
    
    # Per-class metrics
    print(f"\n9. Per-Class Performance:")
    print("-" * 60)
    unique_labels = sorted(set(true_labels))
    
    for label in unique_labels:
        label_mask = [tl == label for tl in true_labels]
        label_true = [tl for tl, mask in zip(true_labels, label_mask) if mask]
        label_pred = [pred for pred, mask in zip(predictions, label_mask) if mask]
        label_conf = [conf for conf, mask in zip(confidences, label_mask) if mask]
        
        if label_true:
            label_acc = accuracy_score(label_true, label_pred)
            label_avg_conf = np.mean(label_conf)
            
            print(f"\n{label.upper()}:")
            print(f"  Samples: {len(label_true)}")
            print(f"  Accuracy: {label_acc:.4f} ({label_acc*100:.2f}%)")
            print(f"  Avg Confidence: {label_avg_conf:.4f} ({label_avg_conf*100:.2f}%)")
            
            # Show common misclassifications
            misclassified = {}
            for true, pred in zip(label_true, label_pred):
                if true != pred:
                    misclassified[pred] = misclassified.get(pred, 0) + 1
            
            if misclassified:
                print(f"  Misclassified as:")
                for pred_label, count in sorted(misclassified.items(), 
                                               key=lambda x: x[1], reverse=True):
                    print(f"    - {pred_label}: {count} times")
    
    # Classification report
    print(f"\n10. Detailed Classification Report:")
    print("=" * 60)
    print(classification_report(true_labels, predictions, digits=4))
    
    # Confusion Matrix
    print(f"\n11. Confusion Matrix:")
    print("-" * 60)
    cm = confusion_matrix(true_labels, predictions, labels=unique_labels)
    
    # Print confusion matrix
    print(f"\n{'':12}", end='')
    for label in unique_labels:
        print(f"{label[:10]:>10}", end=' ')
    print()
    print("-" * (12 + 11 * len(unique_labels)))
    
    for i, label in enumerate(unique_labels):
        print(f"{label[:12]:12}", end='')
        for j in range(len(unique_labels)):
            print(f"{cm[i][j]:>10}", end=' ')
        print()
    
    # Save results
    print(f"\n12. Saving evaluation results...")
    try:
        with open('model_evaluation.txt', 'w') as f:
            f.write("URL DETECTION MODEL - EVALUATION RESULTS\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Test samples: {len(test_sample)}\n")
            f.write(f"Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)\n")
            f.write(f"Average Confidence: {avg_confidence:.4f}\n\n")
            
            f.write("TEST SAMPLE DISTRIBUTION:\n")
            f.write(str(test_sample['label'].value_counts()) + "\n\n")
            
            f.write("PER-CLASS PERFORMANCE:\n")
            f.write("-" * 60 + "\n")
            for label in unique_labels:
                label_mask = [tl == label for tl in true_labels]
                label_true = [tl for tl, mask in zip(true_labels, label_mask) if mask]
                label_pred = [pred for pred, mask in zip(predictions, label_mask) if mask]
                
                if label_true:
                    label_acc = accuracy_score(label_true, label_pred)
                    f.write(f"\n{label}: {label_acc:.4f} ({len(label_true)} samples)\n")
            
            f.write("\n\nCLASSIFICATION REPORT:\n")
            f.write("-" * 60 + "\n")
            f.write(classification_report(true_labels, predictions, digits=4))
        
        print("   ✓ Evaluation results saved to 'model_evaluation.txt'")
    except Exception as e:
        print(f"   ✗ Error saving results: {e}")
    
    # Show example predictions
    print(f"\n13. Sample Predictions:")
    print("=" * 60)
    
    for label in unique_labels[:2]:  # Show examples from first 2 classes
        print(f"\n{label.upper()} examples:")
        print("-" * 60)
        label_samples = test_sample[test_sample['label'] == label].head(3)
        
        for _, row in label_samples.iterrows():
            result = detector.predict(row['url'])
            is_correct = result['prediction'] == row['label']
            symbol = "✓" if is_correct else "✗"
            
            print(f"\n{symbol} URL: {row['url'][:60]}...")
            print(f"   True: {row['label']}")
            print(f"   Predicted: {result['prediction']} (Confidence: {result['confidence']:.2%})")
            
            if not is_correct:
                sorted_probs = sorted(result['probabilities'].items(), 
                                    key=lambda x: x[1], reverse=True)
                print(f"   All probabilities: {sorted_probs}")
    
    # Run sample URL tests
    test_sample_urls(detector)
    
    print("\n" + "=" * 60)
    print("TRAINING AND EVALUATION COMPLETE!")
    print("=" * 60)
    
    # Check model files
    print("\nModel files created:")
    model_files = ['model.pkl', 'vectorizer.pkl', 'label_encoder.pkl']
    for file in model_files:
        if os.path.exists(file):
            size = os.path.getsize(file) / (1024 * 1024)  # Size in MB
            print(f"  ✓ {file} ({size:.2f} MB)")
        else:
            print(f"  ✗ {file} (missing)")
    
    # Final recommendations
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS:")
    print("=" * 60)
    
    if accuracy < 0.85:
        print("⚠ Accuracy below 85%")
        print("  Consider:")
        print("  - Increasing training data size")
        print("  - Adjusting class balancing")
        print("  - Feature engineering")
    elif accuracy < 0.90:
        print("✓ Good accuracy (85-90%)")
        print("  Model is performing reasonably well")
    else:
        print("✓✓ Excellent accuracy (>90%)")
        print("  Model is performing very well")
    
    # Check for class-specific issues
    for label in unique_labels:
        label_mask = [tl == label for tl in true_labels]
        label_true = [tl for tl, mask in zip(true_labels, label_mask) if mask]
        label_pred = [pred for pred, mask in zip(predictions, label_mask) if mask]
        
        if label_true:
            label_acc = accuracy_score(label_true, label_pred)
            if label_acc < 0.70:
                print(f"\n⚠ Low accuracy for '{label}' class: {label_acc:.2%}")
                print(f"  Consider collecting more diverse '{label}' samples")

if __name__ == '__main__':
    try:
        train_and_evaluate()
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()