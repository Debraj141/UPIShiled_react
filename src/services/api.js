import axios from "axios";

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL;
const networkBaseUrl = `${window.location.protocol}//${window.location.hostname}:8000`;

const api = axios.create({
  baseURL: configuredBaseUrl || (import.meta.env.DEV ? networkBaseUrl : ""),
  timeout: 15000
});

export async function analyzeScreenshot(file) {
  const body = new FormData();
  body.append("file", file);
  const { data } = await api.post("/api/v1/analyze", body);
  return data;
}

export async function getHistory() {
  const { data } = await api.get("/api/v1/history");
  return data;
}

export async function getHealth() {
  const { data } = await api.get("/health");
  return data;
}

export default api;