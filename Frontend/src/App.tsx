import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { DownloadButton } from "@/components/DownloadButton";
import Index from "./pages/Index";
import ApiDocs from "./pages/ApiDocs";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const Navigation = () => {
  const location = useLocation();
  const handleDownload = () => {
    // TODO: Add download link
    window.open('#', '_blank');
  };

  return (
    <nav className="fixed top-0 right-0 z-50 pr-8 py-6">
      <div className="flex items-center gap-10">
        <Link 
          to="/" 
          className={`font-cyber text-base tracking-wider px-2 ${location.pathname === '/' ? 'text-white/90' : 'text-white/60'} hover:text-cyber-blue transition-all`}
        >
          ANALYZER
        </Link>
        <Link 
          to="/api-docs" 
          className={`font-cyber text-base tracking-wider px-2 ${location.pathname === '/api-docs' ? 'text-white/90' : 'text-white/60'} hover:text-cyber-blue transition-all`}
        >
          API DOCS
        </Link>
        <div className="w-px h-5 bg-white/10" /> {/* Divider */}
        <DownloadButton onClick={handleDownload} />
      </div>
    </nav>
  );
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <div className="min-h-screen bg-black">
          {/* Background Grid */}
          <div className="fixed inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:50px_50px] pointer-events-none"></div>
          
          <Navigation />

          <main className="relative pt-16">
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/api-docs" element={<ApiDocs />} />
              {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
