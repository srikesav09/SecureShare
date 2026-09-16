import { BrowserRouter } from "react-router-dom";

export function AppRoutes({ children }) {
  return <BrowserRouter>{children}</BrowserRouter>;
}
