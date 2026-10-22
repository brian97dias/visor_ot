import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import ProtectedRoute from "./components/ProtectedRoute";
import AppLayout from "./components/AppLayout";

import Dashboard from "./pages/Dashboard";
import PassiveAnalysis from "./pages/PassiveAnalysis";
import Login from "./pages/Login";
import AnalysisDetail from "./pages/AnalysisDetail";
import IngestionDetail from "./pages/IngestionDetail";
import Communications from "./pages/Communications";
import CommunicationDetail from "./pages/CommunicationDetail";
import Assets from "./pages/Assets";
import AssetImport from "./pages/AssetImport";
import AssetDetail from "./pages/AssetDetail";
import AssetCpeDiscovery from "./pages/AssetCpeDiscovery";
import CpeOverview from "./pages/CpeOverview";
import AssetEditor from "./pages/AssetEditor";
import Interfaces from "./pages/Interfaces";
import InterfaceDetail from "./pages/InterfaceDetail";
import Systems from "./pages/Systems";
import SystemDetail from "./pages/SystemDetail";
import SystemEditor from "./pages/SystemEditor";


function App() {
  return (
    <BrowserRouter>

      <Routes>

        <Route
          path="/login"
          element={<Login />}
        />


        <Route
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >

          <Route
            index
            element={
              <Navigate
                to="/dashboard"
                replace
              />
            }
          />


          <Route
            path="/dashboard"
            element={<Dashboard />}
          />


          <Route
            path="/passive-analysis"
            element={<PassiveAnalysis />}
          />


          <Route
            path="/passive-analysis/:pcapId"
            element={<AnalysisDetail />}
          />


          <Route
            path="/passive-analysis/imports/:ingestionId"
            element={<IngestionDetail />}
          />


          <Route
            path="/ingestion"
            element={
              <Navigate
                to="/passive-analysis"
                replace
              />
            }
          />


          <Route
            path="/communications"
            element={<Communications />}
          />


          <Route
            path="/communications/:communicationId"
            element={<CommunicationDetail />}
          />

          <Route path="/assets" element={<Assets />} />
          <Route path="/assets/import" element={<AssetImport />} />
          <Route path="/assets/interfaces" element={<Interfaces />} />
          <Route path="/assets/interfaces/:interfaceId" element={<InterfaceDetail />} />
          <Route path="/assets/systems" element={<Systems />} />
          <Route path="/assets/systems/new" element={<SystemEditor />} />
          <Route path="/assets/systems/:systemId" element={<SystemDetail />} />
          <Route path="/assets/systems/:systemId/edit" element={<SystemEditor />} />
          <Route path="/assets/hardware" element={<Navigate to="/assets?type=HARDWARE" replace />} />
          <Route path="/assets/new" element={<AssetEditor />} />
          <Route path="/assets/:assetId" element={<AssetDetail />} />
          <Route path="/assets/:assetId/edit" element={<AssetEditor />} />
          <Route path="/assets/:assetId/cpe" element={<AssetCpeDiscovery />} />
          <Route path="/vulnerabilities/cpe" element={<CpeOverview />} />

        </Route>


        <Route
          path="*"
          element={
            <Navigate
              to="/dashboard"
              replace
            />
          }
        />

      </Routes>

    </BrowserRouter>
  );
}


export default App;