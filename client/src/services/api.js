import axios from "axios";

const configuredBaseUrl =
  import.meta.env.VITE_API_URL || "https://api.srikesav.site";
const baseURL = configuredBaseUrl.replace(/\/+$/, "").replace(/\/api$/, "");

const api = axios.create({ baseURL });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("secureshare_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default api;
