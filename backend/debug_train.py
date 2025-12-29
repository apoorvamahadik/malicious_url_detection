# debug_train.py
import sys
import os
import traceback

print("Starting debug...")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"Files in current directory: {os.listdir('.')}")

try:
    # Add parent directory to path
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print("\nAdded parent directory to sys.path")
    
    print("\nTrying to import model module...")
    from model import URLDetector
    print("Successfully imported URLDetector")
    
    print("\nCreating detector instance...")
    detector = URLDetector()
    print("Detector created successfully")
    
except Exception as e:
    print(f"\nERROR: {e}")
    traceback.print_exc()
    
    # Try to import directly
    print("\nTrying direct import...")
    try:
        import model
        print(f"Model module found: {model}")
        URLDetector = model.URLDetector
        detector = URLDetector()
        print("Direct import successful")
    except Exception as e2:
        print(f"Direct import also failed: {e2}")
        traceback.print_exc()