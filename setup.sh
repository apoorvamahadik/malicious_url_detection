#!/bin/bash

echo "Setting up Malicious URL Detection System..."
echo "==========================================="

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Check for dataset
echo "Checking for dataset..."
if [ ! -f "backend/data/malicious_phish.csv" ]; then
    echo "Dataset not found!"
    echo "Please download 'malicious_phish.csv' and place it in backend/data/"
    echo "You can download it from: [DATASET_URL]"
    exit 1
fi

# Train model
echo "Training machine learning model..."
cd backend
python train_model.py

echo ""
echo "Setup complete!"
echo ""
echo "To start the backend server:"
echo "  cd backend && python app.py"
echo ""
echo "To launch the frontend:"
echo "  Open frontend/index.html in your browser"
echo "  Or use: cd frontend && python -m http.server 8080"
echo ""
echo "Access the application at: http://localhost:8080"