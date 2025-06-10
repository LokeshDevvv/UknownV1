import React from 'react';
import { motion } from 'framer-motion';
import { Terminal, Zap, BarChart2, Shield } from 'lucide-react';
import SwaggerDocs from '@/components/SwaggerDocs';

const ApiDocs = () => {
  return (
    <div className="w-full">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="text-center mb-10 mt-10 md:mt-20"
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
        className="container mx-auto px-4 py-8"
      >
        <div className="bg-[#212121] rounded-lg p-8 shadow-lg mb-8">
          <h2 className="text-3xl font-cyber text-cyber-blue mb-4 text-left">API OVERVIEW</h2>
          <p className="text-white leading-relaxed mb-6">
            The Soteria API provides advanced phishing detection capabilities through machine learning and security vendor integrations.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <Shield className="w-10 h-10 text-white mx-auto mb-2" />
              <h3 className="text-xl font-cyber text-white mb-2">SECURE</h3>
              <p className="text-white text-base">End-to-end encrypted communication</p>
            </div>
            <div className="text-center">
              <Zap className="w-10 h-10 text-white mx-auto mb-2" />
              <h3 className="text-xl font-cyber text-white mb-2">FAST</h3>
              <p className="text-white text-base">Real-time threat analysis</p>
            </div>
            <div className="text-center">
              <BarChart2 className="w-10 h-10 text-white mx-auto mb-2" />
              <h3 className="text-xl font-cyber text-white mb-2">SCALABLE</h3>
              <p className="text-white text-base">Bulk analysis support</p>
            </div>
          </div>
        </div>

        {/* Swagger UI Integration */}
        <SwaggerDocs />
      </motion.div>
    </div>
  );
};

export default ApiDocs; 