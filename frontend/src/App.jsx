import { useState, useEffect } from "react";
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
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [localTime, setLocalTime] = useState(new Date());

  const apiBase = import.meta.env.VITE_API_URL || "";

  // Live clock that updates every second
  useEffect(() => {
    const timer = setInterval(() => setLocalTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

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

        {/* Right side controls — intentionally minimal */}
        <div className="flex items-center gap-4 text-xs text-[#54595d]">
          <span className="hover:underline cursor-pointer text-[#3366cc]" onClick={() => setShowAbout(true)}>About</span>
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
            <p className="mb-2">
              🕒 Local time: <span className="font-semibold text-[#202122]">{localTime.toLocaleString()}</span>
            </p>
            <p className="mb-2">Text is available under the Creative Commons Attribution-ShareAlike License; additional terms may apply.</p>
          </div>
          <div className="flex gap-4">
            <span className="hover:underline cursor-pointer text-[#3366cc]" onClick={() => setShowPrivacy(true)}>Privacy policy</span>
            <span className="hover:underline cursor-pointer text-[#3366cc]" onClick={() => setShowAbout(true)}>About CryptoPulse</span>
          </div>
        </div>
      </footer>

      {/* ── Privacy Policy Modal ── */}
      {showPrivacy && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/40" onClick={() => setShowPrivacy(false)}>
          <div className="bg-white border border-[#a2a9b1] rounded-sm shadow-lg w-full max-w-xl p-8 relative" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setShowPrivacy(false)} className="absolute top-3 right-4 text-lg text-[#54595d] hover:text-black cursor-pointer">✕</button>
            <h2 className="font-serif text-2xl text-black mb-4 border-b border-[#a2a9b1] pb-2">Privacy Policy</h2>
            <div className="text-sm leading-relaxed text-[#202122] space-y-3">
              <p>
                CryptoPulse is designed with your privacy in mind. The scanner <strong>does not copy, store, or transmit your source code</strong> to any external service.
              </p>
              <p>
                When you submit a repository URL or upload a ZIP archive, the tool clones or extracts the files into a temporary directory on the server, scans the code exclusively for <strong>cryptographic components and quantum-vulnerable patterns</strong>, and then <strong>immediately deletes</strong> the temporary copy once the analysis is complete.
              </p>
              <p>
                The only data retained is the resulting Cryptographic Bill of Materials (CBOM) — a structured summary of the algorithms detected — which is returned to your browser and never persisted on the server.
              </p>
              <p>
                No personal information, authentication tokens, or code content is collected, logged, or shared with third parties.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── About CryptoPulse Modal ── */}
      {showAbout && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/40" onClick={() => setShowAbout(false)}>
          <div className="bg-white border border-[#a2a9b1] rounded-sm shadow-lg w-full max-w-xl p-8 relative" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setShowAbout(false)} className="absolute top-3 right-4 text-lg text-[#54595d] hover:text-black cursor-pointer">✕</button>
            <h2 className="font-serif text-2xl text-black mb-4 border-b border-[#a2a9b1] pb-2">About CryptoPulse</h2>
            <div className="text-sm leading-relaxed text-[#202122] space-y-3">
              <p>
                <strong>CryptoPulse</strong> is an open-source Cryptographic Bill of Materials (CBOM) generator built to help developers and security teams prepare for the post-quantum era.
              </p>
              <p>
                <strong>What it does:</strong> It scans your source code — via a GitHub URL or a local ZIP upload — and identifies every cryptographic algorithm, library call, and key-management pattern used in your project. Each finding is classified as <em>Quantum Vulnerable</em>, <em>Classically Weak</em>, or <em>Quantum Safe</em>, scored for risk, and enriched with NIST migration recommendations.
              </p>
              <p>
                <strong>Why it was built:</strong> Quantum computers threaten to break widely-used public-key algorithms such as RSA and ECC. Organisations that rely on these algorithms need a clear inventory of where they appear so they can plan a migration to post-quantum cryptography (PQC). CryptoPulse automates that inventory — turning days of manual auditing into a single scan that takes seconds.
              </p>
              <p>
                The project combines <strong>regex-based pattern detection</strong>, a <strong>machine-learning classifier</strong>, and <strong>LLM-powered enrichment</strong> (via Groq) to deliver a comprehensive, actionable CBOM aligned with NIST PQC standards.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
