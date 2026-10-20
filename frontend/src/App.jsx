import React, { useState, useEffect, useCallback } from 'react'
import useWebSocketPkg, { ReadyState } from 'react-use-websocket'
const useWebSocket = useWebSocketPkg.default || useWebSocketPkg
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps"
import { Shield, Activity, MapPin, AlertTriangle, ArrowRight } from 'lucide-react'
import './index.css'

const WS_URL = 'ws://127.0.0.1:8000/ws'
const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json"

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return <div style={{ color: 'red', padding: '20px' }}>
        <h1>Something went wrong.</h1>
        <pre>{this.state.error.toString()}</pre>
      </div>;
    }
    return this.props.children;
  }
}

function App() {
  const [alerts, setAlerts] = useState([])
  const [markers, setMarkers] = useState([])

  const { lastJsonMessage, readyState } = useWebSocket(WS_URL, {
    shouldReconnect: (closeEvent) => true,
    reconnectAttempts: 10,
    reconnectInterval: 3000,
  })

  const connectionStatus = {
    [ReadyState.CONNECTING]: 'Connecting',
    [ReadyState.OPEN]: 'Connected Live',
    [ReadyState.CLOSING]: 'Closing',
    [ReadyState.CLOSED]: 'Disconnected',
    [ReadyState.UNINSTANTIATED]: 'Uninstantiated',
  }[readyState]

  useEffect(() => {
    if (lastJsonMessage && lastJsonMessage.type === "alert") {
      const newAlert = {
        ...lastJsonMessage,
        id: Date.now().toString() + Math.random().toString(),
        timestamp: new Date().toLocaleTimeString()
      }
      
      setAlerts(prev => [newAlert, ...prev].slice(0, 50)) // keep last 50
      
      // Add map marker if geo exists
      if (newAlert.geo && newAlert.geo.lon && newAlert.geo.lat) {
        setMarkers(prev => [
          ...prev, 
          { markerOffset: -15, name: newAlert.src_ip, coordinates: [newAlert.geo.lon, newAlert.geo.lat] }
        ].slice(-20)) // keep last 20 markers
      }
    }
  }, [lastJsonMessage])

  return (
    <div className="dashboard-container">
      <header className="header">
        <h1><Shield className="text-blue-400" /> ThreatScope IDS</h1>
        
        <div className={`status-badge ${readyState !== ReadyState.OPEN ? 'disconnected' : ''}`}>
          <div className="pulse"></div>
          {connectionStatus}
        </div>
      </header>

      <div className="main-grid">
        <div className="panel">
          <h2><MapPin size={20} /> Live Threat Origin Map</h2>
          <div className="map-container">
            <ComposableMap
              projectionConfig={{
                scale: 147
              }}
              style={{ width: "100%", height: "100%" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="rgba(255, 255, 255, 0.05)"
                      stroke="rgba(255, 255, 255, 0.1)"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "rgba(59, 130, 246, 0.2)", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>
              
              {markers.map(({ name, coordinates, markerOffset }, i) => (
                <Marker key={i} coordinates={coordinates}>
                  <circle r={4} fill="#ef4444" stroke="#fff" strokeWidth={1} />
                  {/* Ripple effect */}
                  <circle r={10} fill="none" stroke="#ef4444" strokeWidth={1} opacity={0.5}>
                    <animate attributeName="r" from="4" to="20" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />
                  </circle>
                  <text
                    textAnchor="middle"
                    y={markerOffset}
                    style={{ fontFamily: "monospace", fill: "#f8fafc", fontSize: "10px" }}
                  >
                    {name}
                  </text>
                </Marker>
              ))}
            </ComposableMap>
          </div>
        </div>

        <div className="panel">
          <h2><AlertTriangle size={20} /> Real-time Anomalies</h2>
          
          <div className="alerts-container">
            {alerts.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', marginTop: '2rem' }}>
                <Activity size={32} opacity={0.5} style={{ margin: '0 auto 1rem' }} />
                <p>Monitoring network traffic...</p>
                <p style={{ fontSize: '0.8rem' }}>Waiting for anomalies</p>
              </div>
            ) : (
              alerts.map(alert => (
                <div key={alert.id} className="alert-card">
                  <div className="alert-header">
                    <span className="alert-time">{alert.timestamp}</span>
                    <span className="alert-prob">{(alert.attack_prob * 100).toFixed(1)}% Threat Score</span>
                  </div>
                  
                  <div className="alert-ips">
                    {alert.src_ip} <ArrowRight size={14} color="var(--text-muted)" /> {alert.dst_ip}
                  </div>
                  
                  <div className="alert-geo">
                    <MapPin size={12} />
                    {alert.geo.country !== 'Unknown' 
                      ? `${alert.geo.city}, ${alert.geo.country}` 
                      : 'Unknown Location'} 
                    <span style={{ marginLeft: 'auto', background: 'rgba(255,255,255,0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                      {alert.protocol}
                    </span>
                  </div>

                  {alert.top_features && (
                    <div className="shap-features">
                      <div className="shap-title">Top Contributing Features (SHAP)</div>
                      {alert.top_features.map((f, i) => (
                        <div key={i} className="shap-item">
                          <span className="shap-name">{f.feature}</span>
                          <span className="shap-val">+{f.impact.toFixed(3)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AppWithErrorBoundary() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  )
}
