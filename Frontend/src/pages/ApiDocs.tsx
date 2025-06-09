import { motion } from 'framer-motion';
import { Terminal, Code, Server, Database, Zap, Lock } from 'lucide-react';
import { DownloadButton } from '@/components/DownloadButton';
import { Link } from 'react-router-dom';
import { Layout } from '@/components/Layout';

const ApiDocs = () => {
  const endpoints = [
    {
      method: 'POST',
      path: '/api/analyze',
      description: 'Analyze a single URL for phishing threats',
      request: {
        body: {
          url: 'https://example.com'
        }
      },
      response: {
        url: 'https://example.com',
        risk_level: 'High Risk',
        total_score: 85,
        features: {
          reasons: [
            'Suspicious domain detected',
            'SSL certificate issues'
          ],
          vendor_alerts: [
            'Reported as phishing by security vendors'
          ]
        }
      }
    },
    {
      method: 'POST',
      path: '/api/analyze-bulk',
      description: 'Analyze multiple URLs in bulk',
      request: {
        body: {
          urls: [
            'https://example1.com',
            'https://example2.com'
          ]
        }
      },
      response: [
        {
          url: 'https://example1.com',
          risk_level: 'Low Risk',
          total_score: 15
        },
        {
          url: 'https://example2.com',
          risk_level: 'High Risk',
          total_score: 90
        }
      ]
    },
    {
      method: 'GET',
      path: '/api/health',
      description: 'Check API health status',
      response: {
        status: 'healthy',
        version: '1.0'
      }
    }
  ];

  const handleDownload = () => {
    // TODO: Add download link
    window.open('#', '_blank');
  };

  return (
    <div className="w-full">
      {/* Main Container */}
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center mb-20"
        >
          <div className="inline-flex items-center gap-4 mb-6">
            <motion.div
              animate={{ 
                scale: [1, 1.05, 1],
                rotate: [0, 2, 0]
              }}
              transition={{ 
                duration: 2,
                repeat: Infinity,
                repeatType: "reverse"
              }}
            >
              <Terminal className="w-12 h-12 text-white" />
            </motion.div>
            <h1 className="text-4xl md:text-6xl font-cyber font-bold text-white">
              API DOCS
            </h1>
          </div>
          <p className="text-xl md:text-2xl font-display text-white/60 mb-6">
            Soteria API Documentation
          </p>
          <div className="text-sm font-cyber tracking-wider text-white/40">
            ▲ SECURE ENDPOINT DOCUMENTATION ▲
          </div>
        </motion.div>

        {/* API Overview */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="max-w-4xl mx-auto mb-16"
        >
          <div className="glassmorphism rounded-xl p-8 mb-8">
            <h2 className="text-2xl font-cyber text-white mb-4 flex items-center gap-2">
              <Server className="w-6 h-6" />
              API OVERVIEW
            </h2>
            <div className="space-y-4 text-white/70">
              <p>
                The Soteria API provides advanced phishing detection capabilities through
                machine learning and security vendor integrations.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="glassmorphism p-4 rounded-lg border border-white/10">
                  <div className="flex items-center gap-2 mb-2">
                    <Lock className="w-5 h-5 text-cyber-green" />
                    <span className="font-cyber text-white">SECURE</span>
                  </div>
                  <p className="text-sm text-white/60">End-to-end encrypted communication</p>
                </div>
                <div className="glassmorphism p-4 rounded-lg border border-white/10">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="w-5 h-5 text-cyber-yellow" />
                    <span className="font-cyber text-white">FAST</span>
                  </div>
                  <p className="text-sm text-white/60">Real-time threat analysis</p>
                </div>
                <div className="glassmorphism p-4 rounded-lg border border-white/10">
                  <div className="flex items-center gap-2 mb-2">
                    <Database className="w-5 h-5 text-cyber-blue" />
                    <span className="font-cyber text-white">SCALABLE</span>
                  </div>
                  <p className="text-sm text-white/60">Bulk analysis support</p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Endpoints */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="max-w-4xl mx-auto"
        >
          {endpoints.map((endpoint, index) => (
            <motion.div
              key={endpoint.path}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.4 + index * 0.1 }}
              className="glassmorphism rounded-xl p-8 mb-8 border border-white/10"
            >
              <div className="flex items-center gap-4 mb-6">
                <span className={`font-mono font-bold px-3 py-1 rounded ${
                  endpoint.method === 'GET' ? 'bg-cyber-green/20 text-cyber-green' :
                  'bg-cyber-blue/20 text-cyber-blue'
                }`}>
                  {endpoint.method}
                </span>
                <code className="font-mono text-white/90">{endpoint.path}</code>
              </div>
              
              <p className="text-white/70 mb-6">{endpoint.description}</p>
              
              {endpoint.request && (
                <div className="mb-6">
                  <h3 className="text-sm font-cyber text-white/60 mb-2">REQUEST BODY</h3>
                  <pre className="bg-black/30 rounded-lg p-4 font-mono text-sm text-white/80 overflow-x-auto">
                    {JSON.stringify(endpoint.request.body, null, 2)}
                  </pre>
                </div>
              )}
              
              <div>
                <h3 className="text-sm font-cyber text-white/60 mb-2">RESPONSE</h3>
                <pre className="bg-black/30 rounded-lg p-4 font-mono text-sm text-white/80 overflow-x-auto">
                  {JSON.stringify(endpoint.response, null, 2)}
                </pre>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  );
};

export default ApiDocs; 