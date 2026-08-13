import express from "express";
import cors from "cors";

import healthRoutes from "./routes/health.routes.js";
import authRoutes from "./routes/auth.routes.js";
import { errorHandler } from "./middleware/error.middleware.js";
import fileRoutes from "./routes/file.routes.js";
import shareRoutes from "./routes/share.routes.js";
import publicRoutes from "./routes/public.routes.js"

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/health",healthRoutes);
app.use("/api/auth",authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/share", shareRoutes);
app.use("/share", publicRoutes);

app.use(errorHandler);

export default app;
