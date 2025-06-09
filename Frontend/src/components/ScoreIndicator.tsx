import { motion } from 'framer-motion';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface ScoreIndicatorProps {
  score: number;
  riskLevel: 'safe' | 'moderate' | 'high';
}

export const ScoreIndicator = ({ score, riskLevel }: ScoreIndicatorProps) => {
  const getScoreColor = () => {
    if (score < 20) return 'text-cyber-green';
    if (score < 50) return 'text-cyber-yellow';
    return 'text-cyber-red';
  };

  const getRiskIcon = () => {
    switch (riskLevel) {
      case 'safe':
        return <CheckCircle className="w-6 h-6 text-cyber-green" />;
      case 'moderate':
        return <AlertTriangle className="w-6 h-6 text-cyber-yellow" />;
      case 'high':
        return <AlertTriangle className="w-6 h-6 text-cyber-red" />;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className="glassmorphism rounded-xl p-6"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
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
            <Shield className="w-8 h-8 text-white" />
          </motion.div>
          <div>
            <h3 className="text-lg font-cyber text-white/80 tracking-wider">
              THREAT SCORE
            </h3>
            <div className="flex items-center gap-2">
              {getRiskIcon()}
              <span className={`text-2xl font-bold ${getScoreColor()}`}>
                {score}
              </span>
              <span className="text-sm text-white/40">/ 100</span>
            </div>
          </div>
        </div>

        <div className="relative w-28 h-28">
          <svg className="w-full h-full" viewBox="0 0 100 100">
            {/* Background circle */}
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="rgba(255, 255, 255, 0.1)"
              strokeWidth="6"
            />
            {/* Progress circle */}
            <motion.circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={riskLevel === 'safe' ? 'hsl(142, 76%, 36%)' : 
                     riskLevel === 'moderate' ? 'hsl(45, 93%, 47%)' : 
                     'hsl(0, 84%, 60%)'}
              strokeWidth="6"
              strokeLinecap="round"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: score / 100 }}
              transition={{ duration: 1, ease: "easeInOut" }}
              style={{
                filter: 'drop-shadow(0 0 8px rgba(255, 255, 255, 0.1))'
              }}
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="text-2xl font-cyber font-bold"
              style={{ color: riskLevel === 'safe' ? 'hsl(142, 76%, 36%)' : 
                              riskLevel === 'moderate' ? 'hsl(45, 93%, 47%)' : 
                              'hsl(0, 84%, 60%)' }}
            >
              {score}
            </motion.div>
          </div>
        </div>
      </div>
    </motion.div>
  );
};
