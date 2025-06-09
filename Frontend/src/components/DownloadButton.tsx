import { motion } from 'framer-motion';
import { Download } from 'lucide-react';

interface DownloadButtonProps {
  onClick?: () => void;
}

export const DownloadButton = ({ onClick }: DownloadButtonProps) => {
  return (
    <motion.button
      onClick={onClick}
      className="font-cyber text-base tracking-wider text-white/60 hover:text-cyber-blue transition-all flex items-center gap-3 px-2"
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
    >
      <Download className="w-5 h-5" />
      <span>EXTENSION</span>
    </motion.button>
  );
}; 