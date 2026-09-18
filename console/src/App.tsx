import { Route, Routes } from "react-router-dom";
import { Nav } from "./components/Nav";
import { Fleet } from "./pages/Fleet";
import { Incidents } from "./pages/Incidents";
import { Control } from "./pages/Control";
import { IdsEvaluation } from "./pages/IdsEvaluation";

export default function App() {
  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Nav />
      <Routes>
        <Route path="/" element={<Fleet />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/ids-evaluation" element={<IdsEvaluation />} />
        <Route path="/control" element={<Control />} />
      </Routes>
    </div>
  );
}
