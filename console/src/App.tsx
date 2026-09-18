import { Route, Routes } from "react-router-dom";
import { Nav } from "./components/Nav";
import { Fleet } from "./pages/Fleet";
import { Incidents } from "./pages/Incidents";
import { Control } from "./pages/Control";
import { IdsEvaluation } from "./pages/IdsEvaluation";
import { Sensor } from "./pages/Sensor";
import { DeviceControl } from "./pages/DeviceControl";

export default function App() {
  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      <Nav />
      <Routes>
        <Route path="/" element={<IdsEvaluation />} />
        <Route path="/fleet" element={<Fleet />} />
        <Route path="/live" element={<Fleet />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/device-control" element={<DeviceControl />} />
        <Route path="/sensor" element={<Sensor />} />
        <Route path="/control" element={<Control />} />
      </Routes>
    </div>
  );
}
