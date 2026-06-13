import { useEffect, useState } from "react";

const MESSAGES = [
  "Cloning repository...",
  "Extracting files...",
  "Running regex scanner...",
  "ML classifier analyzing snippets...",
  "Scoring quantum risk...",
  "Generating CBOM report...",
];

export default function LoadingScreen() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 95) return 95;
        const remaining = 98 - prev;
        const increment = Math.max(0.1, remaining * 0.04);
        return Math.min(95, prev + increment);
      });
    }, 150);

    return () => clearInterval(progressInterval);
  }, []);

  const currentMessage = (() => {
    if (progress < 15) return MESSAGES[0];
    if (progress < 35) return MESSAGES[1];
    if (progress < 60) return MESSAGES[2];
    if (progress < 75) return MESSAGES[3];
    if (progress < 90) return MESSAGES[4];
    return MESSAGES[5];
  })();

  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] gap-8 p-6 max-w-md mx-auto">
      {/* Wiki Loading Icon */}
      <div className="relative flex items-center justify-center w-20 h-20">
        <div className="absolute rounded-full h-14 w-14 border-4 border-[#3366cc] border-t-transparent animate-spin"></div>
        <svg className="w-6 h-6 text-[#202122]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
        </svg>
      </div>

      {/* Message and progress */}
      <div className="w-full text-center space-y-3">
        <div className="text-xs font-bold text-[#54595d] tracking-widest uppercase animate-pulse">
          Compiling Report...
        </div>
        <div className="text-base font-medium text-black h-8">
          {currentMessage}
        </div>
      </div>

      {/* Wiki-themed Progress Bar */}
      <div className="w-full space-y-2">
        <div className="w-full bg-[#eaecf0] border border-[#a2a9b1] rounded-sm h-4 overflow-hidden shadow-inner">
          <div
            className="bg-[#3366cc] h-full transition-all duration-300 ease-out"
            style={{ width: `${progress}%` }}
          ></div>
        </div>
        <div className="flex justify-between text-xs font-semibold text-[#54595d] px-1">
          <span>Retrieving catalog data</span>
          <span>{Math.round(progress)}%</span>
        </div>
      </div>
    </div>
  );
}
