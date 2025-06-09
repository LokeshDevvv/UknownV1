import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertTriangle, CheckCircle, X } from 'lucide-react';

interface RiskOverlayProps {
  riskLevel: 'safe' | 'moderate' | 'high';
  onClose: () => void;
}

export const RiskOverlay = ({ riskLevel, onClose }: RiskOverlayProps) => {
  const getRiskConfig = () => {
    switch (riskLevel) {
      case 'safe':
        return {
          icon: CheckCircle,
          color: 'text-cyber-green',
          bgColor: 'bg-cyber-green/5',
          borderColor: 'border-cyber-green/20',
          title: 'SAFE',
          message: 'No immediate threats detected'
        };
      case 'moderate':
        return {
          icon: AlertTriangle,
          color: 'text-cyber-yellow',
          bgColor: 'bg-cyber-yellow/5',
          borderColor: 'border-cyber-yellow/20',
          title: 'CAUTION',
          message: 'Potential risks identified'
        };
      case 'high':
        return {
          icon: AlertTriangle,
          color: 'text-cyber-red',
          bgColor: 'bg-cyber-red/5',
          borderColor: 'border-cyber-red/20',
          title: 'DANGER',
          message: 'High risk threats detected'
        };
    }
  };

  const config = getRiskConfig();
  const IconComponent = config.icon;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          transition={{ type: "spring", damping: 20, stiffness: 300 }}
          className={`relative max-w-lg w-full glassmorphism rounded-xl p-8 ${config.borderColor} border`}
        >
          <button
            onClick={onClose}
            className="absolute top-4 right-4 p-2 rounded-full hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5 text-white/40" />
          </button>

          <div className="flex flex-col items-center text-center space-y-6">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", damping: 10, stiffness: 200, delay: 0.1 }}
            >
              <IconComponent className={`w-16 h-16 ${config.color}`} />
            </motion.div>

            <div className="space-y-2">
              <motion.h2
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.2 }}
                className={`text-3xl font-cyber font-bold ${config.color}`}
              >
                {config.title}
              </motion.h2>
              <motion.p
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.3 }}
                className="text-lg font-display text-white/60"
              >
                {config.message}
              </motion.p>
            </div>

            <motion.div
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="flex items-center gap-2 text-sm font-cyber text-white/40"
            >
              <Shield className="w-4 h-4" />
              <span>CYBER SHIELD PROTECTION ACTIVE</span>
            </motion.div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};
