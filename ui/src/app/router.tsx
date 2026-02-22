import { Routes, Route } from "react-router-dom";
import Layout from "../components/Layout";
import Dashboard from "../pages/Dashboard";
import SessionDetail from "../pages/SessionDetail";
import Diagnostics from "../pages/Diagnostics";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/sessions/:id" element={<SessionDetail />} />
        <Route path="/diagnostics" element={<Diagnostics />} />
      </Routes>
    </Layout>
  );
}
