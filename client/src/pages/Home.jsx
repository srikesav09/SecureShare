import { useEffect, useState } from "react";
import api from "../services/api";
import StatusCard from "../components/StatusCard";

function Home() {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const { data } = await api.get("/health");
        setStatus(data);
      } catch (error) {
        console.error("Health check failed:", error);
      }
    };

    fetchHealth();
  }, []);

  return (
    <main className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      {status ? (
        <StatusCard status={status} />
      ) : (
        <p className="text-slate-300">Connecting to backend...</p>
      )}
    </main>
  );
}

export default Home;