import axios from "axios";
import { Capacitor } from "@capacitor/core";

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL;
const networkBaseUrl = `${window.location.protocol}//${window.location.hostname}:8000`;
const nativeApiBaseUrl = "https://upishield-a07o.onrender.com";

const api = axios.create({
  baseURL: configuredBaseUrl || (
    Capacitor.isNativePlatform()
      ? nativeApiBaseUrl
      : import.meta.env.DEV
        ? networkBaseUrl
        : ""
  ),
  timeout: 90000
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