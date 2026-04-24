/**
 * App.jsx — GuardianBox Root Component
 */

import React from "react";
import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import UploadPage   from "./components/UploadPage";
import DownloadPage from "./components/DownloadPage";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <header className="app-header">
          <Link to="/" className="logo-link">
            <div className="logo">
              <span className="logo-icon">🛡️</span>
              <span className="logo-text">GuardianBox</span>
            </div>
          </Link>
          <nav className="header-nav">
            <span className="header-badge">Zero-Knowledge · AES-256-GCM</span>
          </nav>
        </header>

        <main className="app-main">
          <Routes>
            <Route path="/"         element={<UploadPage />} />
            <Route path="/file/:id" element={<DownloadPage />} />
          </Routes>
        </main>

        <footer className="app-footer">
          <p>GuardianBox — End-to-End Encrypted File Sharing</p>
          <p className="footer-sub">
            Files are encrypted in your browser using AES-256-GCM.
            The server never sees your files or keys.
          </p>
        </footer>
      </div>
    </BrowserRouter>
  );
}
