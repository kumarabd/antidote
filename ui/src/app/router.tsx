import { Routes, Route } from "react-router-dom";
import Layout from "../components/Layout";
import ErrorBoundary from "../components/ErrorBoundary";
import Dashboard from "../pages/Dashboard";
import AppDetail from "../pages/AppDetail";
import RootDetail from "../pages/RootDetail";
import Diagnostics from "../pages/Diagnostics";
import Privacy from "../pages/Privacy";

export default function App() {
  return (
    <ErrorBoundary>
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/apps/:app" element={<AppDetail />} />
        <Route path="/roots/:id" element={<RootDetail />} />
        <Route path="/diagnostics" element={<Diagnostics />} />
        <Route path="/privacy" element={<Privacy />} />
      </Routes>
    </Layout>
    </ErrorBoundary>
  );
}
