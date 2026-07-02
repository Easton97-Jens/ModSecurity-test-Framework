# Security-Data-Flow-Cases

Diese connector-neutralen Framework-Cases modellieren Security- und Data-Flow-Anforderungen. Sie sind Framework-Cases, keine Connector-Implementierung. PASS darf nur durch echte Connector-Runtime-Ausführung und Connector-eigene Evidence entstehen. Event- und Decision-Checks dürfen keine Request- oder Response-Body-Payloads in Logs erlauben. Hash-Chain-Checks sind Evidence- und Tamper-Detection-Checks; echte Manipulationssicherheit benötigt später HMAC/Signatur im Connector.
