import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";


import healthRoutes from "./routes/health.routes.js";
import authRoutes from "./routes/auth.routes.js";
import { errorHandler } from "./middleware/error.middleware.js";
import fileRoutes from "./routes/file.routes.js";
import shareRoutes from "./routes/share.routes.js";
import publicRoutes from "./routes/public.routes.js"
import { requestId } from "./middleware/requestID.middleware.js";
import adminRoutes from "./routes/admin.routes.js";


const app = express();

const allowedOrigins = [
  "https://secureshare.srikesav.site",
  "http://localhost:5173",
];

app.use(
  cors({
    origin: allowedOrigins,
  })
);

app.use(express.json());

app.use((req, res, next) => {
    if (req.path.startsWith("/api/")) {
        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, proxy-revalidate"
        );

        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
    }

    next();
});


app.set("trust proxy",1);
app.use(requestId);

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        },
        contentSecurityPolicy: false,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true
        }
    })
);
app.disable("x-powered-by");


app.use("/api/health",healthRoutes);
app.use("/api/auth",authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/share", shareRoutes);
app.use("/share", publicRoutes);
app.use("/api/admin", adminRoutes);

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            message: "Invalid file upload"
        });
    }

    next(err);
});

app.use(errorHandler);

export default app;
