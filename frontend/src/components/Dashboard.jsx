import { useMemo, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

export default function Dashboard({ cbom }) {
  const [filter, setFilter] = useState("all");
  const stats = cbom.summary || {};
  const components = cbom.components || [];

  const filtered = useMemo(() => {
    if (filter === "all") return components;
    if (filter === "quantum_vulnerable")
      return components.filter((c) => c.classification === "quantum_vulnerable");
    if (filter === "classically_weak")
      return components.filter((c) => c.classification === "classically_weak");
    if (filter === "ml_detected") return components.filter((c) => c.detection_method === "ml");
    return components;
  }, [components, filter]);

  const pieData = [
    { name: "Quantum Vulnerable", value: stats.quantum_vulnerable_count || 0 },
    { name: "Classically Weak", value: stats.classically_weak_count || 0 },
    { name: "Quantum Safe", value: stats.quantum_safe_count || 0 },
    { name: "Key Risk", value: stats.key_risk_count || 0 },
  ];

  // Wikipedia themed chart colors
  const colors = ["#d33", "#ac6600", "#148668", "#6b21a8"];

  // Build a per-file risk score by summing all component scores found in that file
  const fileRiskMap = components.reduce((acc, c) => {
    const fn = c.occurrences?.[0]?.filename || "";
    acc[fn] = (acc[fn] || 0) + (c.risk_score || 0);
    return acc;
  }, {});

  const barData = (stats.top_risk_files || []).map((f) => ({
    file: f.split("/").pop(), // display only filename for clean layout
    fullPath: f,
    score: Math.round(fileRiskMap[f] || 0),
  }));

  function downloadJson() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(cbom, null, 2));
    const a = document.createElement("a");
    a.href = dataStr;
    a.download = "cbom.json";
    a.click();
  }

  const urgency = stats.migration_urgency || "low";
  const urgencyLabel = urgency.toUpperCase();
  
  // Count unique algorithms that actually need migration (vulnerable + weak + key_risk)
  const needMigration = components.filter(
    (c) => c.classification === "quantum_vulnerable" || c.classification === "classically_weak"
  );
  const migrationCount = needMigration.length;

  // Top component for NIST recommendation: prefer quantum_vulnerable, then classically_weak, then anything
  const topMigrationComp =
    [...needMigration].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0] ||
    [...components].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];

  const nistRecommendation = topMigrationComp?.llm_analysis?.nist_standard || null;
  const topAlgoName = topMigrationComp?.name || "";

  return (
    <div className="space-y-6">
      {/* Title block */}
      <div className="pb-3 border-b border-[#a2a9b1] mb-6">
        <h1 className="wiki-heading text-3xl text-black font-serif mb-1">Cryptographic Profile Report</h1>
        <p className="text-sm text-[#54595d] italic">
          From CryptoPulse, the free cryptographic catalog and vulnerability index.
        </p>
      </div>

      {/* Wikipedia Template Notice Box (Warning banner) */}
      {(urgency === "critical" || urgency === "high") && (
        <div className="border border-[#a2a9b1] border-l-[12px] border-l-[#d33] bg-[#f8f9fa] p-4 text-sm flex gap-4 items-start shadow-sm rounded-sm">
          <div className="text-2xl text-[#d33] font-bold">⚠️</div>
          <div className="space-y-1">
            <p className="font-bold text-black">
              This repository has been flagged for urgent cryptographic review.
            </p>
            <p className="text-[#202122]">
              {migrationCount > 0
                ? <>The analysis shows it relies on <strong>{migrationCount}</strong> vulnerable or weak cryptographic components. Top risk is <strong>{topAlgoName}</strong>. A migration to <strong>{nistRecommendation || "a NIST PQC algorithm"}</strong> is recommended under NIST standards.</>
                : <>The analysis detected <strong>{stats.key_risk_count || 0}</strong> potential hardcoded key/credential risk(s) in source files. Review and rotate any exposed secrets immediately.</>
              }
            </p>
          </div>
        </div>
      )}

      {/* Main Grid Layout */}
      <div className="flex gap-6 items-start">
        {/* Left Column - Article content */}
        <div className="flex-1 min-w-0 space-y-8">
          
          {/* Section 1: Summary */}
          <section id="summary">
            <h2 className="wiki-section-title text-xl font-serif">1. Summary</h2>
            <div className="text-sm leading-relaxed text-[#202122] space-y-4">
              <p>
                This document provides an automatically compiled Cryptographic Bill of Materials (CBOM) for the project. 
                A scan was performed across the codebase to identify library imports, cryptographic functions, and potential key management risks.
              </p>
              <p>
                In total, <strong>{cbom.metadata?.files_scanned || 0}</strong> files were scanned, revealing 
                <strong> {cbom.metadata?.total_findings || 0}</strong> cryptographic occurrences. 
                The repository has been evaluated with an Overall Risk Score of <strong>{Math.round(stats.overall_risk_score || 0)} / 100</strong>, 
                giving it a migration urgency classification of <strong className="uppercase">{urgency}</strong>.
              </p>
            </div>
          </section>

          {/* Section 2: Risk Posture */}
          <section id="vulnerabilities">
            <h2 className="wiki-section-title text-xl font-serif">2. Risk Posture</h2>
            <div className="grid grid-cols-2 gap-4">
              {/* Doughnut Chart */}
              <div className="border border-[#a2a9b1] p-4 rounded-sm bg-white shadow-sm flex flex-col items-center">
                <span className="text-xs font-bold text-[#202122] mb-3 block">Algorithm Classification Breakdown</span>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" innerRadius={40} outerRadius={65} paddingAngle={2}>
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value, name) => [value, name]} />
                  </PieChart>
                </ResponsiveContainer>
                {/* Custom Wiki Legend */}
                <div className="flex flex-wrap gap-3 text-xs font-semibold mt-3">
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#d33]" /> Vulnerable ({stats.quantum_vulnerable_count || 0})</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#ac6600]" /> Weak ({stats.classically_weak_count || 0})</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#148668]" /> Safe ({stats.quantum_safe_count || 0})</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#6b21a8]" /> Key Risk ({stats.key_risk_count || 0})</span>
                </div>
              </div>

              {/* Bar Chart */}
              <div className="border border-[#a2a9b1] p-4 rounded-sm bg-white shadow-sm flex flex-col items-center">
                <span className="text-xs font-bold text-[#202122] mb-3 block">Top Risk Files (Risk Score)</span>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={barData} layout="vertical">
                    <XAxis type="number" hide />
                    <YAxis dataKey="file" type="category" width={90} style={{ fontSize: '10px' }} />
                    <Tooltip formatter={(value) => [`Score: ${value}`, "Risk Score"]} />
                    <Bar dataKey="score" fill="#3366cc" radius={[0, 2, 2, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </section>

          {/* Section 3: Component Inventory */}
          <section id="inventory">
            <h2 className="wiki-section-title text-xl font-serif">3. Component Inventory</h2>
            
            {/* Wiki Filter Tabs */}
            <div className="text-xs border-b border-[#eaecf0] pb-2 mb-4 flex gap-3 text-[#54595d]">
              <span className="font-bold text-[#202122]">Filter views:</span>
              <button onClick={() => setFilter("all")} className={`hover:underline ${filter === "all" ? "text-black font-bold" : "text-[#3366cc]"}`}>All ({components.length})</button>
              <span>|</span>
              <button onClick={() => setFilter("quantum_vulnerable")} className={`hover:underline ${filter === "quantum_vulnerable" ? "text-black font-bold" : "text-[#3366cc]"}`}>Vulnerable ({stats.quantum_vulnerable_count || 0})</button>
              <span>|</span>
              <button onClick={() => setFilter("classically_weak")} className={`hover:underline ${filter === "classically_weak" ? "text-black font-bold" : "text-[#3366cc]"}`}>Weak ({stats.classically_weak_count || 0})</button>
              <span>|</span>
              <button onClick={() => setFilter("key_risk")} className={`hover:underline ${filter === "key_risk" ? "text-black font-bold" : "text-[#3366cc]"}`}>Key Risk ({stats.key_risk_count || 0})</button>
              <span>|</span>
              <button onClick={() => setFilter("ml_detected")} className={`hover:underline ${filter === "ml_detected" ? "text-black font-bold" : "text-[#3366cc]"}`}>ML Detected ({stats.ml_detected_count || 0})</button>
            </div>

            {/* Table */}
            <div className="border border-[#a2a9b1] rounded-sm overflow-hidden bg-white shadow-sm">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-[#eaecf0] border-b border-[#a2a9b1] text-black font-serif">
                    <th className="p-3 border-r border-[#eaecf0]">File</th>
                    <th className="p-3 border-r border-[#eaecf0] w-16 text-center">Line</th>
                    <th className="p-3 border-r border-[#eaecf0]">Algorithm</th>
                    <th className="p-3 border-r border-[#eaecf0]">Classification</th>
                    <th className="p-3 border-r border-[#eaecf0] w-20 text-center">Source</th>
                    <th className="p-3 w-16 text-center">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((c, idx) => (
                    <ExpandableRow key={idx} comp={c} />
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Section 4: NIST Recommendations */}
          {topMigrationComp && (
            <section id="migration">
              <h2 className="wiki-section-title text-xl font-serif">4. NIST PQC Recommendations</h2>
              <div className="border border-[#a2a9b1] p-5 rounded-sm bg-[#f8f9fa] shadow-sm space-y-4 text-sm">
                <div>
                  <h4 className="font-bold text-black mb-1">Top Risk Component: {topAlgoName}</h4>
                  <p className="text-[#54595d] text-xs">Classified as <span className="text-red-700 font-bold uppercase">{topMigrationComp.classification?.replace("_", " ")}</span></p>
                </div>
                <div className="border-t border-[#eaecf0] pt-3">
                  <span className="font-bold text-black block mb-1">Risk Explanation:</span>
                  <p className="text-[#202122]">{topMigrationComp.llm_analysis?.risk_explanation}</p>
                </div>
                <div className="border-t border-[#eaecf0] pt-3">
                  <span className="font-bold text-black block mb-1">NIST Migration Target:</span>
                  <p className="text-[#202122] font-semibold text-green-700">{nistRecommendation}</p>
                  <p className="text-[#202122] mt-2">{topMigrationComp.llm_analysis?.migration_recommendation}</p>
                </div>
              </div>
            </section>
          )}

        </div>

        {/* Right Column - Wikipedia Infobox */}
        <aside className="w-80 flex-shrink-0 border border-[#a2a9b1] bg-[#f8f9fa] p-4 text-xs space-y-4 rounded-sm shadow-sm">
          <div className="text-center font-serif font-bold border-b border-[#a2a9b1] pb-2 text-sm text-black uppercase tracking-wide">
            Cryptographic Profile
          </div>
          <table className="w-full text-left border-collapse">
            <tbody>
              {/* Overall Risk */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Risk Rating</th>
                <td className="py-2.5">
                  <span className={`px-2 py-0.5 rounded-sm text-white font-bold text-[10px] ${stats.overall_risk_score > 75 ? "bg-[#d33]" : stats.overall_risk_score > 50 ? "bg-[#ac6600]" : "bg-[#148668]"}`}>
                    {Math.round(stats.overall_risk_score || 0)} / 100
                  </span>
                </td>
              </tr>
              {/* Migration Urgency */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Migration Urgency</th>
                <td className={`py-2.5 font-bold uppercase ${urgency === "critical" || urgency === "high" ? "text-red-600" : "text-[#148668]"}`}>
                  {urgencyLabel}
                </td>
              </tr>
              {/* Vulnerable */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Quantum Vulnerable</th>
                <td className="py-2.5 text-red-600 font-bold">{stats.quantum_vulnerable_count || 0}</td>
              </tr>
              {/* Weak */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Classically Weak</th>
                <td className="py-2.5 text-[#ac6600] font-bold">{stats.classically_weak_count || 0}</td>
              </tr>
              {/* Quantum Safe */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Quantum Safe</th>
                <td className="py-2.5 text-green-700 font-bold">{stats.quantum_safe_count || 0}</td>
              </tr>
              {/* Files Scanned */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Files Scanned</th>
                <td className="py-2.5 text-black font-semibold">{cbom.metadata?.files_scanned || 0}</td>
              </tr>
              {/* Total Findings */}
              <tr className="border-b border-[#eaecf0]">
                <th className="py-2.5 pr-2 font-bold text-[#202122]">Total Findings</th>
                <td className="py-2.5 text-black font-semibold">{cbom.metadata?.total_findings || 0}</td>
              </tr>
            </tbody>
          </table>

          {/* Download block */}
          <button
            onClick={downloadJson}
            className="w-full mt-4 bg-white border border-[#a2a9b1] hover:bg-gray-50 text-[#202122] py-2 px-4 text-xs font-bold text-center block rounded-sm shadow-sm cursor-pointer transition-colors"
          >
            Download CBOM JSON
          </button>
        </aside>
      </div>
    </div>
  );
}

function ExpandableRow({ comp }) {
  const [open, setOpen] = useState(false);
  const firstOcc = comp.occurrences?.[0] || {};
  const filename = firstOcc.filename || "unknown";
  
  const classificationColors = {
    quantum_vulnerable: "bg-red-100 text-red-800 border-red-200",
    classically_weak: "bg-orange-100 text-orange-800 border-orange-200",
    quantum_safe: "bg-green-100 text-green-800 border-green-200",
    key_risk: "bg-purple-100 text-purple-800 border-purple-200"
  };

  const badgeColor = classificationColors[comp.classification] || "bg-gray-100 text-gray-800";

  return (
    <>
      <tr onClick={() => setOpen((s) => !s)} className="cursor-pointer border-b border-[#eaecf0] hover:bg-[#f8f9fa] transition-colors">
        <td className="p-3 border-r border-[#eaecf0] text-[#3366cc] font-medium break-all hover:underline">{filename}</td>
        <td className="p-3 border-r border-[#eaecf0] text-center text-[#54595d]">{firstOcc.line_number || "?"}</td>
        <td className="p-3 border-r border-[#eaecf0] font-mono text-black font-semibold">{comp.name}</td>
        <td className="p-3 border-r border-[#eaecf0]">
          <span className={`px-2 py-0.5 border rounded-sm font-semibold text-[10px] uppercase ${badgeColor}`}>
            {comp.classification?.replace("_", " ")}
          </span>
        </td>
        <td className="p-3 border-r border-[#eaecf0] text-center"><span className="px-1.5 py-0.5 bg-gray-100 text-gray-700 rounded-sm font-bold text-[9px] uppercase">{comp.detection_method}</span></td>
        <td className="p-3 text-center font-bold text-black">{Math.round(comp.risk_score || 0)}</td>
      </tr>
      {open && (
        <tr className="bg-[#f8f9fa] border-b border-[#eaecf0]">
          <td colSpan={6} className="p-4 space-y-4">
            <div className="space-y-1.5">
              <strong className="block text-xs text-black">Code Snippet:</strong>
              <pre className="text-xs p-3 bg-[#1e1e1e] text-[#d4d4d4] rounded-sm font-mono overflow-x-auto shadow-inner leading-relaxed">
                {firstOcc.code_snippet}
              </pre>
            </div>
            {comp.llm_analysis && (
              <div className="grid grid-cols-2 gap-4 border-t border-[#eaecf0] pt-3">
                <div className="space-y-1">
                  <strong className="block text-xs text-black">Risk Explanation:</strong>
                  <p className="text-xs text-[#202122] leading-relaxed">{comp.llm_analysis.risk_explanation}</p>
                </div>
                <div className="space-y-1">
                  <strong className="block text-xs text-black">Migration Recommendation:</strong>
                  <p className="text-xs text-[#202122] leading-relaxed">{comp.llm_analysis.migration_recommendation}</p>
                </div>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
