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
import "./App.css";

const App = () => {
  return (
    <Router>
      <Routes>
        {/* RootPage (No Navbar) */}
        <Route path="/" element={<RootPage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        {/* Other Pages (With Navbar) */}
        <Route
          path="/*"
          element={
            <>
              <Navbar />
              <Routes>
                <Route path="/home" element={<Home />} />
                <Route path="/scan-url" element={<ScanURL />} />
                <Route path="/scan-email" element={<ScanEmail />} />
                <Route path="/education" element={<Education />} />
                <Route path="/change-plan" element={<ChangePlan />} />

              </Routes>
            </>
          }
        />
      </Routes>
    </Router>
  );
};

export default App;
