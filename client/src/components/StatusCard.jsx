function StatusCard({ status }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg w-full max-w-md">
      <h2 className="text-2xl font-semibold text-blue-500 mb-4">
        Backend Status
      </h2>

      <p className="text-emerald-400 font-medium">
        🟢 {status.message}
      </p>

      <p className="text-slate-400 mt-2">
        Version: {status.version}
      </p>
    </div>
  );
}

export default StatusCard;