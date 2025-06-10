from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields, reqparse
from flask_cors import CORS
from phish_detector import PhishingDetector
import asyncio
import logging
from urllib.parse import urlparse

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
    prefix='/api'
)

# Create namespaces
ns = api.namespace('', description='PhishEvil operations')

# Initialize phishing detector
detector = PhishingDetector()

# Define models for Swagger documentation
url_model = api.model('URL', {
    'url': fields.String(required=True, description='URL to analyze')
})

urls_model = api.model('URLs', {
    'urls': fields.List(fields.String, required=True, description='List of URLs to analyze')
})

analysis_result = api.model('AnalysisResult', {
    'url': fields.String(description='Analyzed URL'),
    'domain': fields.String(description='Domain of the URL'),
    'protocol': fields.String(description='Protocol of the URL'),
    'path': fields.String(description='Path of the URL'),
    'port': fields.Integer(description='Port of the URL'),
    'risk_level': fields.String(description='Risk level assessment'),
    'total_score': fields.Float(description='Total risk score'),
    'features': fields.Raw(description='Detailed feature analysis')
})

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
            result = asyncio.run(detector.analyze_url(url))
            logger.debug('Analysis result: %s', result)
            # Build response using new structure
            return {
                'url': result['url'],
                'domain': result.get('domain', ''),
                'protocol': result.get('protocol', ''),
                'path': result.get('path', ''),
                'port': result.get('port', 80),
                'risk_level': result.get('risk_level', 'Unknown'),
                'total_score': result.get('total_score', 0),
                'features': result.get('features', {}),
                'gsb_checked': result.get('gsb_checked', False),
                'virustotal_checked': result.get('virustotal_checked', False)
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

if __name__ == '__main__':
    print("Starting PhishEvil API server...")
    print("API documentation available at: http://localhost:5000/docs")
    print("Press Ctrl+C to stop the server")
    app.run(debug=True, host='0.0.0.0', port=5000) 