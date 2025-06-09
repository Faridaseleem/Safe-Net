import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./pages/Home";
import ScanURL from "./pages/ScanURL";
import ScanEmail from "./pages/ScanEmail";
import Education from "./pages/Education";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import ChangePlan from "./pages/ChangePlan";
import Verify from "./pages/Verify";
import SelectPlan from "./pages/SelectPlan";
import RootPage from "./pages/RootPage";
import ReportURL from "./pages/ReportURL";  // User URL report page
import AdminReportURLs from "./pages/AdminReportedURLs"; // Admin report management page
import Chatbot from "./components/Chatbot"; // NEW: Import Chatbot component**
import "./App.css";

const App = () => {
  return (
    <Router>
      <Routes>
        {/* RootPage (No Navbar) */}
        <Route path="/" element={<RootPage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/verify" element={<Verify />} />
        <Route path="/select-plan" element={<SelectPlan />} />

        {/* Other Pages (With Navbar) */}
        <Route
          path="/*"
          element={
            <>
              <Navbar />
              <Chatbot />
              <Routes>
                <Route path="/home" element={<Home />} />
                <Route path="/scan-url" element={<ScanURL />} />
                <Route path="/scan-email" element={<ScanEmail />} />
                <Route path="/education" element={<Education />} />
                <Route path="/change-plan" element={<ChangePlan />} />
                <Route path="/report-url" element={<ReportURL />} />  {/* User report */}
                <Route path="/admin/reports" element={<AdminReportURLs />} /> {/* Admin manage */}
              </Routes>
               {/* NEW: Mount Chatbot on pages with Navbar** */}
            </>
          }
        />
      </Routes>
    </Router>
  );
};

export default App;
