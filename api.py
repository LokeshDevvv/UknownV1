from flask import Flask, redirect, request, jsonify
from flask_restx import Api, Resource, fields, reqparse
from flask_cors import CORS
from phish_detector import PhishingDetector
import json
import asyncio
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enable CORS for all domains with all methods
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept", "Origin"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 600
    }
})

# Initialize API with Swagger documentation
api = Api(
    app,
    version='1.0',
    title='PhishEvil API',
    description='A powerful phishing detection API that analyzes URLs for potential threats',
    doc='/docs',
    prefix='/api'  # Add prefix for all routes
)

# Create namespaces
ns = api.namespace('', description='PhishEvil operations')  # Empty string since we're using prefix

# Initialize phishing detector
detector = PhishingDetector()

# Log all requests
@app.before_request
def log_request_info():
    logger.debug('Headers: %s', dict(request.headers))
    logger.debug('Body: %s', request.get_data())

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    logger.debug('Response headers before: %s', dict(response.headers))
    
    # Allow all origins
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin')
    response.headers.add('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS')
    response.headers.add('Access-Control-Max-Age', '3600')
    
    logger.debug('Response headers after: %s', dict(response.headers))
    return response

# Handle OPTIONS requests explicitly
@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    response = app.make_default_options_response()
    logger.debug('OPTIONS request for path: %s', path)
    return response

# Redirect root to docs
@app.route('/')
def index():
    return redirect('/docs')

# Define models for Swagger documentation
url_model = api.model('URL', {
    'url': fields.String(required=True, description='URL to analyze')
})

urls_model = api.model('URLs', {
    'urls': fields.List(fields.String, required=True, description='List of URLs to analyze')
})

analysis_result = api.model('AnalysisResult', {
    'url': fields.String(description='Analyzed URL'),
    'risk_level': fields.String(description='Risk level assessment'),
    'total_score': fields.Float(description='Total risk score'),
    'features': fields.Raw(description='Detailed feature analysis')
})

# Parser for query parameters
url_parser = reqparse.RequestParser()
url_parser.add_argument('url', type=str, required=True, help='URL to analyze')

@ns.route('/analyze')
class AnalyzeURL(Resource):
    @ns.expect(url_model)
    @ns.marshal_with(analysis_result)
    @ns.doc(
        responses={
            200: 'Success',
            400: 'Invalid URL',
            500: 'Server Error'
        },
        description='Analyze a single URL for phishing threats'
    )
    def post(self):
        """Analyze a single URL for potential phishing threats"""
        logger.debug('Analyze request received')
        data = api.payload
        url = data.get('url')
        
        if not url:
            logger.error('URL is required but not provided')
            api.abort(400, "URL is required")
            
        try:
            logger.debug('Analyzing URL: %s', url)
            # Run the async analysis in the event loop
            result = asyncio.run(detector.analyze_url(url))
            logger.debug('Analysis result: %s', result)
            return {
                'url': result['url'],
                'risk_level': 'High Risk' if result['safety_status'] == 'DANGEROUS' else 'Low Risk',
                'total_score': 100 if result['safety_status'] == 'DANGEROUS' else 0,
                'features': {
                    'reasons': result['details'],
                    'vendor_alerts': result.get('vendor_alerts', [])
                }
            }
        except Exception as e:
            logger.error('Error analyzing URL: %s', str(e), exc_info=True)
            api.abort(500, str(e))

@ns.route('/analyze-bulk')
class AnalyzeURLsBulk(Resource):
    @ns.expect(urls_model)
    @ns.marshal_list_with(analysis_result)
    @ns.doc(
        responses={
            200: 'Success',
            400: 'Invalid Request',
            500: 'Server Error'
        },
        description='Analyze multiple URLs for phishing threats'
    )
    def post(self):
        """Analyze multiple URLs for potential phishing threats"""
        logger.debug('Bulk analyze request received')
        data = api.payload
        urls = data.get('urls', [])
        
        if not urls:
            logger.error('URLs list is required but not provided')
            api.abort(400, "URLs list is required")
            
        try:
            results = []
            for url in urls:
                logger.debug('Analyzing URL in bulk: %s', url)
                # Run the async analysis in the event loop
                result = asyncio.run(detector.analyze_url(url))
                results.append({
                    'url': result['url'],
                    'risk_level': 'High Risk' if result['safety_status'] == 'DANGEROUS' else 'Low Risk',
                    'total_score': 100 if result['safety_status'] == 'DANGEROUS' else 0,
                    'features': {
                        'reasons': result['details'],
                        'vendor_alerts': result.get('vendor_alerts', [])
                    }
                })
            logger.debug('Bulk analysis results: %s', results)
            return results
        except Exception as e:
            logger.error('Error in bulk analysis: %s', str(e), exc_info=True)
            api.abort(500, str(e))

@ns.route('/health')
class HealthCheck(Resource):
    @ns.doc(
        responses={
            200: 'API is healthy',
            500: 'API is not healthy'
        },
        description='Check the health status of the API'
    )
    def get(self):
        """Check if the API is healthy"""
        logger.debug('Health check request received')
        return {'status': 'healthy', 'version': '1.0'}

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url']
        logger.debug(f"Analyzing URL: {url}")
        
        detector = PhishingDetector()
        result = asyncio.run(detector.analyze_url(url))
        
        response = {
            'url': result['url'],
            'risk_level': 'High Risk' if result['safety_status'] == 'DANGEROUS' else 'Low Risk',
            'total_score': 100 if result['safety_status'] == 'DANGEROUS' else 0,
            'features': {
                'reasons': result['details'],
                'vendor_alerts': result.get('vendor_alerts', [])
            }
        }
        
        logger.debug(f"Analysis result: {result}")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze/bulk', methods=['POST'])
def analyze_bulk():
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'URLs are required'}), 400
            
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
            
        results = []
        detector = PhishingDetector()
        
        for url in urls:
            try:
                result = asyncio.run(detector.analyze_url(url))
                response = {
                    'url': result['url'],
                    'risk_level': 'High Risk' if result['safety_status'] == 'DANGEROUS' else 'Low Risk',
                    'total_score': 100 if result['safety_status'] == 'DANGEROUS' else 0,
                    'features': {
                        'reasons': result['details'],
                        'vendor_alerts': result.get('vendor_alerts', [])
                    }
                }
                results.append(response)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e)
                })
                
        logger.debug(f"Bulk analysis results: {results}")
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in bulk analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info('Starting API server on port 5000')
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True) 