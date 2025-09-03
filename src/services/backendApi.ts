export async function fetchAlerts(limit: number = 50) {
  try {
    const res = await fetch(`http://localhost:8000/api/alerts?limit=${limit}`);
    if (!res.ok) {
      console.warn(`Backend API not available: ${res.status}`);
      return [];
    }
    const json = await res.json();
    return json.items ?? [];
  } catch (error) {
    console.warn('Backend API not available:', error);
    return [];
  }
}

export async function healthCheck() {
  try {
    const res = await fetch('http://localhost:8000/api/health');
    if (!res.ok) {
      console.warn(`Backend health check failed: ${res.status}`);
      return { status: 'unhealthy' };
    }
    return res.json();
  } catch (error) {
    console.warn('Backend health check failed:', error);
    return { status: 'unhealthy' };
  }
}
