import { useState } from "react";

export default function UploadZone({ onScanRepo, onUploadZip }) {
  const [githubUrl, setGithubUrl] = useState("");
  const [file, setFile] = useState(null);

  function uploadZip(e) {
    e.preventDefault();
    if (file) {
      onUploadZip(file);
    }
  }

  function scanRepo(e) {
    e.preventDefault();
    const url = githubUrl.trim();
    if (url) {
      onScanRepo(url);
    }
  }

  return (
    <div className="space-y-8">
      {/* Welcome Banner */}
      <div className="pb-6 border-b border-[#a2a9b1]">
        <h1 className="wiki-heading text-4xl text-black mb-2 font-serif">Portal: Cryptographic Asset Scanner</h1>
        <p className="text-sm text-[#54595d] italic">
          From CryptoPulse, the free cryptographic catalog and vulnerability index.
        </p>
      </div>

      {/* Main description paragraph */}
      <div className="text-sm leading-relaxed max-w-3xl space-y-4 text-[#202122]">
        <p>
          Welcome to the <strong>CryptoPulse Portal</strong>. This tool performs deep analysis on software source code to identify and categorize cryptographic components. It distinguishes between 
          <span className="mx-1 px-1.5 py-0.5 bg-red-100 text-red-800 rounded-sm font-semibold">Quantum Vulnerable</span> (RSA, ECC), 
          <span className="mx-1 px-1.5 py-0.5 bg-orange-100 text-orange-800 rounded-sm font-semibold">Classically Weak</span> (MD5, SHA1), and 
          <span className="mx-1 px-1.5 py-0.5 bg-green-100 text-green-800 rounded-sm font-semibold">Quantum Safe</span> (ML-KEM, SLH-DSA, AES-GCM) algorithms.
        </p>
        <p>
          Use either of the sections below to initiate a scan and build a Cryptographic Bill of Materials (CBOM).
        </p>
      </div>

      {/* Structured Wikipedia Cards */}
      <div className="grid grid-cols-2 gap-8 mt-6">
        {/* Repo Scan Block */}
        <div className="border border-[#a2a9b1] bg-white rounded-sm overflow-hidden shadow-sm">
          <div className="bg-[#eaecf0] border-b border-[#a2a9b1] px-4 py-2 font-serif text-base text-black font-semibold">
            Scan Remote GitHub Repository
          </div>
          <div className="p-6 space-y-4">
            <p className="text-xs text-[#54595d]">
              Enter the full URL of a public GitHub repository. The scanner will clone, parse, and analyze it.
            </p>
            <form onSubmit={scanRepo} className="space-y-4">
              <div className="space-y-1">
                <label className="block text-xs font-bold text-[#202122]">GitHub URL</label>
                <input
                  type="text"
                  placeholder="e.g. https://github.com/pyca/cryptography"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  className="w-full px-3 py-1.5 border border-[#a2a9b1] rounded-sm text-sm focus:outline-none focus:border-[#3366cc] bg-white text-black"
                />
              </div>
              <button
                type="submit"
                className="w-full bg-[#3366cc] hover:bg-[#4477dd] text-white text-sm font-bold py-2 px-4 rounded-sm transition-colors duration-150 cursor-pointer shadow-sm"
              >
                Scan Repository
              </button>
            </form>
          </div>
        </div>

        {/* ZIP Upload Block */}
        <div className="border border-[#a2a9b1] bg-white rounded-sm overflow-hidden shadow-sm">
          <div className="bg-[#eaecf0] border-b border-[#a2a9b1] px-4 py-2 font-serif text-base text-black font-semibold">
            Upload Local Source Archive
          </div>
          <div className="p-6 space-y-4">
            <p className="text-xs text-[#54595d]">
              Select a ZIP file containing the source code files of your project to scan locally.
            </p>
            <form onSubmit={uploadZip} className="space-y-4">
              <div className="space-y-1">
                <label className="block text-xs font-bold text-[#202122]">Source ZIP Archive</label>
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  className="w-full px-3 py-1.5 border border-[#a2a9b1] bg-[#f8f9fa] rounded-sm text-sm focus:outline-none text-black"
                />
              </div>
              <button
                type="submit"
                className="w-full bg-[#3366cc] hover:bg-[#4477dd] text-white text-sm font-bold py-2 px-4 rounded-sm transition-colors duration-150 cursor-pointer shadow-sm"
              >
                Scan Upload
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
