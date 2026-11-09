// Where the website finds the PrintFlow backend.
// - Leave empty when the backend itself serves this site (e.g. the Render address).
// - When the site is hosted separately (e.g. on Netlify), put the backend address here,
//   for example: "https://printflow-api.onrender.com"
window.PRINTFLOW_API_URL = location.hostname.endsWith("onrender.com") || location.hostname === "localhost"
  ? ""                                        // served by the backend itself
  : "https://printflow-api-em92.onrender.com"; // Netlify (or any other host) uses the Render backend
