from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from model import predict_url, get_url_info, get_threat_description, get_recommendation
import os

# REMOVE static_folder parameter - use default Flask structure
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# CHANGE THIS: Use render_template instead of send_from_directory
@app.route('/')
def index():
    """Serve the frontend HTML"""
    return render_template('index.html')  # Flask automatically looks in templates/

# Keep all your API routes EXACTLY as they are...
@app.route('/api')
def home():
    return jsonify({
        'message': 'Malicious URL Detection API is running!',
        'version': '3.0',
        'classes': ['benign', 'defacement', 'phishing', 'malware'],
        'endpoints': {
            '/api/predict': 'POST - Predict single URL',
            '/api/batch_predict': 'POST - Predict multiple URLs',
            '/api/health': 'GET - Health check'
        }
    })

@app.route('/api/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Make prediction
        prediction_result = predict_url(url)
        
        # Get additional URL information (in background, don't fail if it errors)
        try:
            url_info = get_url_info(url)
        except:
            url_info = {'error': 'Could not fetch URL info'}
        
        # Get threat description and recommendation
        threat_type = prediction_result['prediction']
        
        response = {
            'url': url,
            'prediction': threat_type,
            'confidence': prediction_result['confidence'],
            'probabilities': prediction_result.get('probabilities', {}),
            'description': get_threat_description(threat_type),
            'recommendation': get_recommendation(threat_type),
            'info': url_info,
            'severity': get_severity_level(threat_type),
            'is_malicious': prediction_result.get('is_malicious', False),
            'whitelist_match': prediction_result.get('whitelist_match', False),
            'phishing_indicators': prediction_result.get('phishing_indicators')
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in predict: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch_predict', methods=['POST'])
def batch_predict():
    try:
        data = request.json
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        # Limit batch size
        if len(urls) > 100:
            return jsonify({'error': 'Maximum 100 URLs per batch'}), 400
        
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
                
            try:
                result = predict_url(url)
                result['url'] = url
                result['description'] = get_threat_description(result['prediction'])
                result['recommendation'] = get_recommendation(result['prediction'])
                result['severity'] = get_severity_level(result['prediction'])
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'prediction': 'error'
                })
        
        # Calculate summary statistics
        summary = {}
        for result in results:
            pred = result.get('prediction', 'error')
            summary[pred] = summary.get(pred, 0) + 1
        
        return jsonify({
            'results': results,
            'summary': summary,
            'total_urls': len(results)
        })
        
    except Exception as e:
        print(f"Error in batch_predict: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Quick test prediction
        test_result = predict_url("https://www.google.com")
        return jsonify({
            'status': 'healthy',
            'model_loaded': True,
            'test_prediction': test_result.get('prediction') == 'benign'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'model_loaded': False,
            'error': str(e)
        }), 500

def get_severity_level(threat_type):
    """Get severity level for threat type"""
    severity = {
        'benign': 'safe',
        'defacement': 'medium',
        'phishing': 'high',
        'malware': 'critical',
        'uncertain': 'low',
        'unknown': 'unknown'
    }
    return severity.get(threat_type, 'unknown')

if __name__ == '__main__':
    print("=" * 60)
    print("Starting Malicious URL Detection API v3.0...")
    print("=" * 60)
    print("Supported threat types: benign, defacement, phishing, malware")
    print("\nEndpoints:")
    print("  - Web UI:        http://localhost:5001/")
    print("  - API Info:      http://localhost:5001/api")
    print("  - Predict:       POST http://localhost:5001/api/predict")
    print("  - Batch Predict: POST http://localhost:5001/api/batch_predict")
    print("  - Health Check:  GET  http://localhost:5001/api/health")
    print("=" * 60)
    
    # REMOVE this line - we're not creating static folder here anymore
    # os.makedirs('static', exist_ok=True)
    
    app.run(debug=True, port=5001, host='0.0.0.0')