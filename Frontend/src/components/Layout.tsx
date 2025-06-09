import { Link } from 'react-router-dom';
import { DownloadButton } from './DownloadButton';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  const handleDownload = () => {
    // TODO: Add download link
    window.open('#', '_blank');
  };

  return (
    <div className="min-h-screen bg-black">
      {/* Background Grid */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:50px_50px] pointer-events-none"></div>

      {/* Navigation */}
      <nav className="fixed top-0 right-0 z-50 pr-4 py-3">
        <div className="flex items-center gap-6">
          <Link to="/" className="font-cyber text-sm text-white/90 hover:text-cyber-blue transition-all">ANALYZER</Link>
          <Link to="/api-docs" className="font-cyber text-sm text-white/60 hover:text-cyber-blue transition-all">API DOCS</Link>
          <div className="w-px h-4 bg-white/10" /> {/* Divider */}
          <DownloadButton onClick={handleDownload} />
        </div>
      </nav>

      {/* Content */}
      <main className="relative pt-16">
        {children}
      </main>
    </div>
  );
}; 