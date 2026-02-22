import { Routes, Route } from "react-router-dom";
import Layout from "../components/Layout";
import ErrorBoundary from "../components/ErrorBoundary";
import Dashboard from "../pages/Dashboard";
import SessionDetail from "../pages/SessionDetail";
import Diagnostics from "../pages/Diagnostics";
import Privacy from "../pages/Privacy";

export default function App() {
  return (
    <ErrorBoundary>
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/sessions/:id" element={<SessionDetail />} />
        <Route path="/diagnostics" element={<Diagnostics />} />
        <Route path="/privacy" element={<Privacy />} />
      </Routes>
    </Layout>
    </ErrorBoundary>
  );
}
