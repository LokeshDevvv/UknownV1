# PhishEvil API

PhishEvil is a powerful phishing detection API that analyzes URLs for potential threats using advanced machine learning techniques.

## Features

- Single URL analysis
- Bulk URL analysis
- Detailed threat assessment
- Risk level classification
- Feature-based analysis
- Swagger documentation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/PhishEvilV2.git
cd PhishEvilV2
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the API

Start the API server:
```bash
python api.py
```

The API will be available at `http://localhost:5000`, and the Swagger documentation can be accessed at `http://localhost:5000/docs`.

## API Endpoints

### 1. Analyze Single URL
- **Endpoint**: `/api/analyze`
- **Method**: POST
- **Request Body**:
```json
{
    "url": "https://example.com"
}
```
- **Response**:
```json
{
    "url": "https://example.com",
    "risk_level": "Low Risk",
    "total_score": 0.2,
    "features": {
        "domain_age": 0.1,
        "ssl_cert": 0.0,
        "...": "..."
    }
}
```

### 2. Analyze Multiple URLs
- **Endpoint**: `/api/analyze-bulk`
- **Method**: POST
- **Request Body**:
```json
{
    "urls": [
        "https://example1.com",
        "https://example2.com"
    ]
}
```
- **Response**: Array of analysis results

### 3. Health Check
- **Endpoint**: `/api/health`
- **Method**: GET
- **Response**:
```json
{
    "status": "healthy",
    "version": "1.0"
}
```

## Response Codes

- 200: Successful request
- 400: Invalid request (missing or invalid parameters)
- 500: Server error

## Risk Levels

- **High Risk** (score > 0.7): Likely phishing attempt
- **Medium Risk** (score 0.4-0.7): Suspicious characteristics
- **Low Risk** (score < 0.4): Likely legitimate

## Development

To run in development mode:
```bash
python api.py
```

## License

[Your License] 