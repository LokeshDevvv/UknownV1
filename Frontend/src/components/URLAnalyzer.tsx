import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Shield, AlertTriangle, CheckCircle, Zap, Globe, Clock, ShieldCheck, ShieldAlert } from 'lucide-react';
import { RiskOverlay } from './RiskOverlay';
import { ScoreIndicator } from './ScoreIndicator';
import { motion, AnimatePresence } from 'framer-motion';

const API_URL = 'http://localhost:5000/api';

interface AnalysisResult {
  url: string;
  riskLevel: 'safe' | 'moderate' | 'high';
  score: number;
  threats: string[];
  analysisTime: number;
}

export const URLAnalyzer = () => {
  const [url, setUrl] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [showOverlay, setShowOverlay] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiConnected, setApiConnected] = useState<boolean>(false);

  useEffect(() => {
    checkApiConnection();
  }, []);

  const checkApiConnection = async () => {
    try {
      const response = await fetch(`${API_URL}/health`);
      if (response.ok) {
        setApiConnected(true);
        setError(null);
      } else {
        setApiConnected(false);
        setError('API service is not responding properly');
      }
    } catch (err) {
      setApiConnected(false);
      setError('Cannot connect to API service. Please ensure the API is running.');
    }
  };

  const mapRiskLevel = (apiRiskLevel: string): 'safe' | 'moderate' | 'high' => {
    switch (apiRiskLevel.toLowerCase()) {
      case 'low risk': return 'safe';
      case 'medium risk': return 'moderate';
      case 'high risk': return 'high';
      default: return 'moderate';
    }
  };

  const mapThreats = (features: Record<string, any>): string[] => {
    const threats: string[] = [];
    
    // Map features to threat descriptions
    if (features.suspicious_tld > 0.5) threats.push('Suspicious top-level domain detected');
    if (features.domain_age < 0.3) threats.push('Recently registered domain');
    if (features.ssl_cert > 0.5) threats.push('SSL certificate issues detected');
    if (features.suspicious_chars > 0.5) threats.push('Suspicious characters in URL');
    if (features.length_based > 0.5) threats.push('Unusual URL length detected');
    if (features.ip_address > 0.5) threats.push('IP address used instead of domain name');
    if (features.special_chars > 0.5) threats.push('Special characters detected in URL');
    
    return threats;
  };

  const analyzeURL = async () => {
    if (!url.trim()) return;
    if (!apiConnected) {
      setError('Cannot analyze URL: API service is not connected');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    const startTime = performance.now();
    
    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Failed to analyze URL');
      }

      const apiResult = await response.json();
      const endTime = performance.now();
      
      if (!apiResult || !apiResult.risk_level) {
        throw new Error('Invalid response from API');
      }
      
      const mappedResult: AnalysisResult = {
        url: apiResult.url,
        riskLevel: mapRiskLevel(apiResult.risk_level),
        score: apiResult.total_score,
        threats: mapThreats(apiResult.features || {}),
        analysisTime: Math.round(endTime - startTime),
      };

      setResult(mappedResult);
      setShowOverlay(true);
      setTimeout(() => setShowOverlay(false), 3000);
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
      if (!apiConnected) {
        checkApiConnection();
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    analyzeURL();
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
              <Shield className="w-12 h-12 text-white" />
            </motion.div>
            <h1 className="text-4xl md:text-6xl font-cyber font-bold text-white">
              SOTERIA
            </h1>
          </div>
          <p className="text-xl md:text-2xl font-display text-white/60 mb-3">
            Phishing Link Analyzer
          </p>
          <div className="text-sm font-cyber tracking-wider text-white/40">
            ▲ AI-POWERED THREAT ANALYSIS ▲
          </div>
        </motion.div>

        {/* Main Interface */}
        <div className="max-w-3xl mx-auto">
          {/* URL Input Section */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="glassmorphism rounded-xl p-8 mb-8"
          >
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <label className="block text-sm font-cyber text-white/60 tracking-wider uppercase">
                    Target URL Analysis
                  </label>
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${apiConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
                    <span className="text-xs font-cyber text-white/40">
                      {apiConnected ? 'API CONNECTED' : 'API DISCONNECTED'}
                    </span>
                  </div>
                </div>
                <div className="relative group">
                  <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 transition-colors group-focus-within:text-white" />
                  <Input
                    type="url"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="pl-12 h-14 text-lg font-display bg-white/5 border-white/10 focus:border-white/20 focus:ring-white/10 rounded-lg transition-all duration-300"
                    disabled={isAnalyzing}
                  />
                </div>
              </div>
              
              <Button
                type="submit"
                disabled={isAnalyzing || !url.trim()}
                className="w-full h-14 text-lg font-cyber font-bold bg-white text-black hover:bg-white/90 disabled:opacity-50 disabled:hover:bg-white transition-all duration-300 rounded-lg"
              >
                {isAnalyzing ? (
                  <div className="flex items-center gap-3">
                    <div className="w-6 h-6 border-2 border-black/30 border-t-black rounded-full animate-spin"></div>
                    ANALYZING THREAT VECTORS...
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <Zap className="w-6 h-6" />
                    INITIATE SCAN
                  </div>
                )}
              </Button>
            </form>
          </motion.div>

          {/* Error Message */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-500 text-center"
            >
              {error}
            </motion.div>
          )}

          {/* Results Section */}
          <AnimatePresence>
            {result && (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.3 }}
                className="space-y-6"
              >
                {/* Score Indicator */}
                <ScoreIndicator score={result.score} riskLevel={result.riskLevel} />

                {/* Detailed Results */}
                <div className="glassmorphism rounded-xl p-8">
                  <div className="grid md:grid-cols-2 gap-8">
                    {/* Analysis Summary */}
                    <div className="space-y-4">
                      <h3 className="text-lg font-cyber text-white/80 tracking-wider flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5" />
                        THREAT ASSESSMENT
                      </h3>
                      <div className="space-y-3">
                        <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg transition-colors hover:bg-white/10">
                          <span className="font-display text-white/60">Risk Level:</span>
                          <span className={`font-cyber font-bold ${
                            result.riskLevel === 'safe' ? 'text-cyber-green' :
                            result.riskLevel === 'moderate' ? 'text-cyber-yellow' :
                            'text-cyber-red'
                          }`}>
                            {result.riskLevel.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg transition-colors hover:bg-white/10">
                          <span className="font-display text-white/60">Analysis Time:</span>
                          <span className="font-cyber text-white/80 flex items-center gap-1">
                            <Clock className="w-4 h-4" />
                            {result.analysisTime}ms
                          </span>
                        </div>
                        <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg transition-colors hover:bg-white/10">
                          <span className="font-display text-white/60">URL Status:</span>
                          <span className="font-cyber text-white/40">SCANNED</span>
                        </div>
                      </div>
                    </div>

                    {/* Threats Detected */}
                    <div className="space-y-4">
                      <h3 className="text-lg font-cyber text-white/80 tracking-wider flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5" />
                        THREAT VECTORS
                      </h3>
                      {result.threats.length > 0 ? (
                        <div className="space-y-2">
                          {result.threats.map((threat, index) => (
                            <motion.div
                              key={index}
                              initial={{ opacity: 0, x: -20 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ duration: 0.3, delay: index * 0.1 }}
                              className="p-3 bg-white/5 rounded-lg text-white/60 font-display flex items-center gap-2"
                            >
                              <AlertTriangle className="w-4 h-4 text-cyber-red" />
                              {threat}
                            </motion.div>
                          ))}
                        </div>
                      ) : (
                        <div className="p-3 bg-white/5 rounded-lg text-white/60 font-display flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-cyber-green" />
                          No threats detected
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Risk Overlay */}
      {showOverlay && result && (
        <RiskOverlay
          riskLevel={result.riskLevel}
          onClose={() => setShowOverlay(false)}
        />
      )}
    </div>
  );
};
