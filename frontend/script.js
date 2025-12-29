const API_URL = 'http://localhost:5001/api';
let probabilityChart = null;

// Color mapping for threat types
const threatColors = {
    benign: '#28a745',
    defacement: '#ffc107',
    phishing: '#fd7e14',
    malware: '#dc3545',
    unknown: '#6c757d'
};

// Severity icons
const threatIcons = {
    benign: 'fa-check-circle',
    defacement: 'fa-exclamation-triangle',
    phishing: 'fa-fish',
    malware: 'fa-bug',
    unknown: 'fa-question-circle'
};

// Sample URLs for testing
const sampleURLs = {
    benign: [
        'https://google.com',
        'https://github.com',
        'https://stackoverflow.com',
        'https://wikipedia.org'
    ],
    phishing: [
        'http://secure-paypal-login.com',
        'http://facebook-login-verify.net',
        'http://amazon-account-update.com'
    ],
    malware: [
        'http://free-software-download.com/install.exe',
        'http://cracked-software.net/keygen.exe'
    ]
};

async function checkURL() {
    const urlInput = document.getElementById('urlInput').value.trim();
    
    if (!urlInput) {
        alert('Please enter a URL');
        return;
    }
    
    // Add http:// if no protocol specified
    let urlToCheck = urlInput;
    if (!urlToCheck.startsWith('http://') && !urlToCheck.startsWith('https://')) {
        urlToCheck = 'http://' + urlToCheck;
    }
    
    showLoading();
    
    try {
        const response = await fetch(`${API_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlToCheck })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
        } else {
            showResult(data);
        }
    } catch (error) {
        showError('Error connecting to the server. Make sure the backend is running on port 5001.');
        console.error('Error:', error);
    }
}

async function checkBatchURLs() {
    const batchInput = document.getElementById('batchInput').value.trim();
    
    if (!batchInput) {
        alert('Please enter at least one URL');
        return;
    }
    
    const urls = batchInput.split('\n')
        .map(url => url.trim())
        .filter(url => url.length > 0)
        .map(url => url.startsWith('http') ? url : 'http://' + url);
    
    if (urls.length > 50) {
        alert('Maximum 50 URLs allowed for batch analysis');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch(`${API_URL}/batch_predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
        } else {
            showBatchResults(data);
        }
    } catch (error) {
        showError('Error connecting to the server. Make sure the backend is running.');
        console.error('Error:', error);
    }
}

function showLoading() {
    const resultSection = document.getElementById('resultSection');
    const resultContainer = document.getElementById('resultContainer');
    
    resultSection.style.display = 'block';
    resultContainer.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p>Analyzing URL for threats...</p>
            <p class="loading-sub">Checking for: Benign, Defacement, Phishing, Malware</p>
        </div>
    `;
    
    // Scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth' });
    
    // Destroy previous chart if exists
    if (probabilityChart) {
        probabilityChart.destroy();
    }
}

function showResult(data) {
    const resultContainer = document.getElementById('resultContainer');
    const threatType = data.prediction.toLowerCase();
    
    // Prepare probability data for chart
    const labels = Object.keys(data.probabilities || {});
    const probabilities = Object.values(data.probabilities || {});
    const backgroundColors = labels.map(label => threatColors[label] || threatColors.unknown);
    
    resultContainer.innerHTML = `
        <div class="result-card ${threatType}">
            <div class="result-header">
                <div>
                    <div class="threat-badge ${threatType}">
                        <i class="fas ${threatIcons[threatType]}"></i>
                        ${threatType.toUpperCase()}
                    </div>
                    <p style="margin-top: 10px; font-size: 0.9rem; color: #666;">
                        <i class="fas fa-info-circle"></i> ${data.description}
                    </p>
                </div>
                <div class="confidence-score">
                    <div style="text-align: right;">
                        <strong>Confidence:</strong>
                        <div style="font-size: 1.5rem; font-weight: bold; color: ${threatColors[threatType]}">
                            ${(data.confidence * 100).toFixed(1)}%
                        </div>
                    </div>
                </div>
            </div>
            
            <div style="margin: 20px 0;">
                <strong>URL:</strong>
                <div style="font-family: monospace; padding: 10px; background: #f8f9fa; border-radius: 5px; margin-top: 5px;">
                    ${data.url}
                </div>
            </div>
            
            <div class="confidence-meter">
                <div class="confidence-fill ${threatType}" style="width: ${data.confidence * 100}%"></div>
            </div>
            
            <div class="details-grid">
                <div class="detail-item">
                    <strong><i class="fas fa-shield-alt"></i> Severity</strong>
                    ${data.severity.toUpperCase()}
                </div>
                <div class="detail-item">
                    <strong><i class="fas fa-globe"></i> IP Address</strong>
                    ${data.info.ip || 'Unknown'}
                </div>
                <div class="detail-item">
                    <strong><i class="fas fa-map-marker-alt"></i> Location</strong>
                    ${data.info.city || 'Unknown'}, ${data.info.country || 'Unknown'}
                </div>
                <div class="detail-item">
                    <strong><i class="fas fa-server"></i> ISP</strong>
                    ${data.info.isp || 'Unknown'}
                </div>
            </div>
            
            <div class="probability-chart">
                <h4><i class="fas fa-chart-bar"></i> Probability Distribution</h4>
                <canvas id="probabilityChart" height="200"></canvas>
            </div>
            
            <div style="margin-top: 25px; padding: 20px; background: ${getAlertColor(threatType)}; color: white; border-radius: 10px;">
                <h4 style="color: white; margin-bottom: 10px;">
                    <i class="fas fa-exclamation-circle"></i> Recommendation
                </h4>
                <p>${data.recommendation}</p>
            </div>
            
            ${data.info.error ? `
                <div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 5px; color: #856404;">
                    <i class="fas fa-exclamation-triangle"></i> Note: ${data.info.error}
                </div>
            ` : ''}
        </div>
    `;
    
    // Create probability chart
    createProbabilityChart(labels, probabilities, backgroundColors);
}

function createProbabilityChart(labels, probabilities, colors) {
    const ctx = document.getElementById('probabilityChart').getContext('2d');
    
    // Destroy previous chart if exists
    if (probabilityChart) {
        probabilityChart.destroy();
    }
    
    probabilityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Probability',
                data: probabilities,
                backgroundColor: colors,
                borderColor: colors.map(color => color.replace('0.8', '1')),
                borderWidth: 1,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${(context.raw * 100).toFixed(2)}%`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 1,
                    ticks: {
                        callback: function(value) {
                            return (value * 100) + '%';
                        }
                    },
                    title: {
                        display: true,
                        text: 'Probability'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Threat Type'
                    }
                }
            }
        }
    });
}

function showBatchResults(data) {
    const resultContainer = document.getElementById('resultContainer');
    const summary = data.summary || {};
    
    // Calculate percentages
    const total = data.total_urls || data.results.length;
    let summaryHTML = '';
    
    for (const [threat, count] of Object.entries(summary)) {
        const percentage = ((count / total) * 100).toFixed(1);
        summaryHTML += `
            <div class="summary-item ${threat}">
                <div style="font-size: 1.5rem; font-weight: bold;">${count}</div>
                <div>${threat.toUpperCase()}</div>
                <div style="font-size: 0.9rem; opacity: 0.8;">${percentage}%</div>
            </div>
        `;
    }
    
    // Create URL list
    let urlListHTML = '';
    data.results.forEach((result, index) => {
        const threatType = result.prediction.toLowerCase();
        urlListHTML += `
            <div class="url-item ${threatType}">
                <span style="color: #666; font-weight: bold;">${index + 1}.</span>
                <div class="url-text">${result.url}</div>
                <span class="url-tag ${threatType}">
                    <i class="fas ${threatIcons[threatType]}"></i>
                    ${threatType.toUpperCase()}
                </span>
            </div>
        `;
    });
    
    resultContainer.innerHTML = `
        <div class="batch-results">
            <h3><i class="fas fa-tasks"></i> Batch Analysis Results</h3>
            <p>Analyzed ${total} URLs</p>
            
            <div class="batch-summary">
                ${summaryHTML}
            </div>
            
            <h4 style="margin-top: 30px;"><i class="fas fa-list-ul"></i> Detailed Results</h4>
            <div class="batch-urls">
                ${urlListHTML}
            </div>
            
            <div style="margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 10px;">
                <strong>Export Results:</strong>
                <button onclick="exportResults()" style="margin-left: 10px; padding: 8px 15px; background: #28a745;">
                    <i class="fas fa-download"></i> Download as CSV
                </button>
            </div>
        </div>
    `;
    
    // Store results for export
    window.batchResults = data.results;
}

function showError(message) {
    const resultContainer = document.getElementById('resultContainer');
    resultContainer.innerHTML = `
        <div class="result-card malware">
            <div class="threat-badge malware">
                <i class="fas fa-exclamation-circle"></i> ERROR
            </div>
            <p style="margin-top: 15px; color: #721c24;">${message}</p>
            <button onclick="showLoading(); setTimeout(checkURL, 100)" style="margin-top: 15px;">
                <i class="fas fa-redo"></i> Try Again
            </button>
        </div>
    `;
}

function useSample(url) {
    document.getElementById('urlInput').value = url;
    checkURL();
}

function getAlertColor(threatType) {
    switch (threatType) {
        case 'benign': return '#28a745';
        case 'defacement': return '#ffc107';
        case 'phishing': return '#fd7e14';
        case 'malware': return '#dc3545';
        default: return '#6c757d';
    }
}

function exportResults() {
    if (!window.batchResults) {
        alert('No results to export');
        return;
    }
    
    // Convert to CSV
    const headers = ['URL', 'Threat Type', 'Confidence', 'Description', 'Recommendation'];
    const rows = window.batchResults.map(result => [
        result.url,
        result.prediction,
        (result.confidence * 100).toFixed(2) + '%',
        result.description,
        result.recommendation
    ]);
    
    const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');
    
    // Create download link
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'url_analysis_results.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Event Listeners
document.addEventListener('DOMContentLoaded', function() {
    // Enter key support
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            checkURL();
        }
    });
    
    // Set up sample URLs placeholder
    const batchInput = document.getElementById('batchInput');
    batchInput.placeholder = 
        "Enter multiple URLs (one per line, max 50)\n\nExample:\nhttps://google.com\nhttps://github.com\nhttp://example-phishing-site.com\nhttp://malware-download-site.net";
    
    // Check if backend is running
    fetch(`${API_URL}/health`)
        .then(response => response.json())
        .then(data => {
            console.log('Backend status:', data);
        })
        .catch(error => {
            console.warn('Backend not running:', error);
            showWarning('Backend server is not running. Please start the Flask server on port 5001.');
        });
});

function showWarning(message) {
    const warning = document.createElement('div');
    warning.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ffc107;
        color: #856404;
        padding: 15px 20px;
        border-radius: 5px;
        box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 10px;
    `;
    warning.innerHTML = `
        <i class="fas fa-exclamation-triangle"></i>
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="margin-left: 10px; background: none; border: none; color: inherit; cursor: pointer;">
            <i class="fas fa-times"></i>
        </button>
    `;
    document.body.appendChild(warning);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (warning.parentElement) {
            warning.remove();
        }
    }, 10000);
}