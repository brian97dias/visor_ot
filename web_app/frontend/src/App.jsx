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