import { useState } from "react";
import UploadZone from "./components/UploadZone";
import LoadingScreen from "./components/LoadingScreen";
import Dashboard from "./components/Dashboard";
import axios from "axios";
import "./App.css";

function App() {
  const [phase, setPhase] = useState("upload");
  const [cbom, setCbom] = useState(null);
  const [error, setError] = useState(null);
  const [searchUrl, setSearchUrl] = useState("");

  const apiBase = import.meta.env.VITE_API_URL || "";

  async function handleScanRepo(url) {
    setError(null);
    setPhase("loading");
    try {
      const res = await axios.post(`${apiBase}/scan/repo`, { github_url: url });
      setCbom(res.data);
      setPhase("results");
    } catch (err) {
      console.error(err);
      setError(err);
      setPhase("upload");
    }
  }

  async function handleUploadZip(file) {
    setError(null);
    setPhase("loading");
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const res = await axios.post(`${apiBase}/scan/upload`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setCbom(res.data);
      setPhase("results");
    } catch (err) {
      console.error(err);
      setError(err);
      setPhase("upload");
    }
  }

  function handleSearchSubmit(e) {
    e.preventDefault();
    if (searchUrl.trim()) {
      handleScanRepo(searchUrl.trim());
      setSearchUrl("");
    }
  }

  return (
    <div className="flex flex-col min-h-screen bg-[#f8f9fa] text-[#202122] font-sans antialiased">
      {/* Wikipedia-like Top Navigation Header */}
      <header className="flex items-center justify-between border-b border-[#a2a9b1] bg-white px-6 py-2 sticky top-0 z-50">
        {/* Left Logo block */}
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => { setPhase("upload"); setCbom(null); setError(null); }}>
          <svg className="w-9 h-9 text-[#202122]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
            <path d="M2 12h20" />
          </svg>
          <div>
            <span className="font-serif text-xl tracking-tight text-black block leading-none">CryptoPulse</span>
            <span className="text-[10px] text-[#54595d] tracking-widest uppercase">The Crypto Wiki</span>
          </div>
        </div>

        {/* Center search/scan input */}
        <form onSubmit={handleSearchSubmit} className="flex items-center w-full max-w-lg border border-[#a2a9b1] bg-white rounded-sm overflow-hidden h-8 shadow-sm">
          <input
            type="text"
            placeholder="Search or enter GitHub URL to scan..."
            value={searchUrl}
            onChange={(e) => setSearchUrl(e.target.value)}
            className="w-full px-3 text-sm focus:outline-none placeholder-gray-400"
          />
          <button type="submit" className="px-4 bg-[#f8f9fa] border-l border-[#a2a9b1] hover:bg-gray-100 text-sm font-medium text-[#202122] h-full flex items-center justify-center">
            Search
          </button>
        </form>

        {/* Right side controls */}
        <div className="flex items-center gap-4 text-xs text-[#54595d]">
          <span className="hover:underline cursor-pointer">Contributions</span>
          <span className="hover:underline cursor-pointer">Talk</span>
          <span className="hover:underline cursor-pointer text-[#3366cc]" onClick={() => { setPhase("upload"); setCbom(null); setError(null); }}>
            Main Portal
          </span>
        </div>
      </header>

      {/* Main Structural Layout */}
      <div className="flex flex-1 flex-row w-full max-w-7xl mx-auto px-4 py-6 gap-6">
        {/* Wikipedia-like Left Sidebar */}
        <aside className="w-48 flex-shrink-0 space-y-6">
          <div className="border-b border-[#eaecf0] pb-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[#54595d] mb-2 px-2">Navigation</h4>
            <nav className="space-y-1">
              <button
                onClick={() => { setPhase("upload"); setCbom(null); setError(null); }}
                className={`wiki-sidebar-link text-left w-full ${phase === "upload" ? "active" : ""}`}
              >
                Main Page
              </button>
              <button
                onClick={() => { setPhase("upload"); setCbom(null); setError(null); }}
                className="wiki-sidebar-link text-left w-full"
              >
                Upload File
              </button>
              <a href="https://github.com/pyca/cryptography" target="_blank" rel="noreferrer" className="wiki-sidebar-link">
                Featured Lib
              </a>
            </nav>
          </div>

          {phase === "results" && cbom && (
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#54595d] mb-2 px-2">Table of Contents</h4>
              <nav className="space-y-1">
                <a href="#summary" className="wiki-sidebar-link">1. Summary Profile</a>
                <a href="#vulnerabilities" className="wiki-sidebar-link">2. Risk Posture</a>
                <a href="#inventory" className="wiki-sidebar-link">3. Components</a>
                <a href="#migration" className="wiki-sidebar-link">4. NIST Migration</a>
              </nav>
            </div>
          )}
        </aside>

        {/* Main Content Pane */}
        <main className="flex-1 min-w-0 bg-white border border-[#a2a9b1] p-8 shadow-sm rounded-sm">
          {phase === "upload" && (
            <UploadZone onScanRepo={handleScanRepo} onUploadZip={handleUploadZip} />
          )}
          {phase === "loading" && <LoadingScreen />}
          {phase === "results" && cbom && <Dashboard cbom={cbom} />}

          {error && (
            <div className="mt-6 p-4 border border-[#e53e3e] bg-[#fff5f5] text-[#c53030] rounded-sm flex gap-3 items-start max-w-2xl mx-auto">
              <svg className="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <strong className="block font-bold">Scan Execution Failed</strong>
                <span className="text-sm">{error.response?.data?.detail || error.message || String(error)}</span>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Wikipedia-like Footer */}
      <footer className="border-t border-[#a2a9b1] bg-[#f8f9fa] mt-12 py-8 px-6 text-xs text-[#54595d] max-w-7xl mx-auto w-full">
        <div className="flex justify-between items-start">
          <div>
            <p className="mb-2">This page was last scanned on {new Date().toLocaleDateString()}.</p>
            <p className="mb-2">Text is available under the Creative Commons Attribution-ShareAlike License; additional terms may apply.</p>
          </div>
          <div className="flex gap-4">
            <span className="hover:underline cursor-pointer">Privacy policy</span>
            <span className="hover:underline cursor-pointer">About CryptoPulse</span>
            <span className="hover:underline cursor-pointer">Disclaimers</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
