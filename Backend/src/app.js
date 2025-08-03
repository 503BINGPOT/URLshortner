import express from 'express';
import dotenv from 'dotenv';
import helmet from 'helmet';
import connectDB from './config/db.js';
import { redirectFromShortUrl } from './controller/short_url.controller.js';
import { errorHandler } from './utils/errorHandler.js';
import cors from 'cors';
import authRoutes from './routers/auth.router.js';
import cookieParser from 'cookie-parser';
import { attachuser } from './utils/attachuser.js';
import user_routes from './routers/user.route.js';
import short_url from './routers/short_url.router.js';
import { globalLimiter, redirectLimiter } from './middleware/rateLimiter.js';

dotenv.config();
const app = express();

// Security middleware - helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Global rate limiting
app.use(globalLimiter);

// CORS configuration
const allowedOrigins = [
    "http://localhost:5173",
    "https://clipli.onrender.com",
    "https://app.clipli.sbs",
    process.env.FRONTEND_URL
].filter(Boolean);

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like curl or mobile apps)
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
};

// ✅ Set CORS middleware first
app.use(cors(corsOptions));

// ✅ Handle preflight OPTIONS requests globally
app.options('*', cors(corsOptions));

// Cookie and body parsing with size limits
app.use(cookieParser());
app.use(express.json({ limit: '10mb' })); // Limit request body size
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Attach user (should be after CORS & body parsing)
app.use(attachuser);

// Connect to DB before handling routes
connectDB();

// Health check
app.get('/health', (_req, res) => {
    res.status(200).json({
        status: 'OK',
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// API routes
app.use("/api/user", user_routes);
app.use("/api/auth", authRoutes);
app.use("/api/create", short_url);

// Short URL redirect (should be last route) with rate limiting
app.get("/:id", redirectLimiter, redirectFromShortUrl);

// Global error handler
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});
