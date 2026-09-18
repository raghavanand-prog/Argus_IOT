import { Route, Routes } from "react-router-dom";
import { Nav } from "./components/Nav";
import { Fleet } from "./pages/Fleet";
import { Incidents } from "./pages/Incidents";
import { Control } from "./pages/Control";
import { IdsEvaluation } from "./pages/IdsEvaluation";
import { LiveNetwork } from "./pages/LiveNetwork";

export default function App() {
  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Nav />
      <Routes>
        <Route path="/" element={<IdsEvaluation />} />
        <Route path="/live" element={<LiveNetwork />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/fleet" element={<Fleet />} />
        <Route path="/control" element={<Control />} />
      </Routes>
    </div>
  );
}
