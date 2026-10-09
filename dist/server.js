"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const json_server_1 = __importDefault(require("json-server"));
const node_path_1 = __importDefault(require("node:path"));
const http_proxy_middleware_1 = require("http-proxy-middleware");
const app = (0, express_1.default)();
const jsonServerApp = json_server_1.default.create();
const dbPath = node_path_1.default.resolve(process.cwd(), 'data/db.json');
jsonServerApp.use(json_server_1.default.defaults());
jsonServerApp.use(json_server_1.default.router(dbPath));
jsonServerApp.listen(3001, '127.0.0.1', () => {
    console.log('json-server running internally on port 3001');
});
const ACCESS_TOKEN_SECRET = 'my-access-secret';
const REFRESH_TOKEN_SECRET = 'my-refresh-secret';
// ======================================================
// Middlewares
// ======================================================
app.use((0, cors_1.default)({
    origin: 'http://localhost:4200',
    credentials: true,
}));
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
// ======================================================
// Health
// ======================================================
app.get('/health', (req, res) => {
    res.json({
        message: 'Backend is running',
    });
});
// ======================================================
// Auth Middleware
// ======================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({
            message: 'Access token is required',
        });
    }
    const token = authHeader.split(' ')[1];
    try {
        const payload = jsonwebtoken_1.default.verify(token, ACCESS_TOKEN_SECRET);
        const userId = Number(payload.sub);
        if (!payload.sub || Number.isNaN(userId)) {
            return res.status(401).json({
                message: 'Invalid access token',
            });
        }
        if (!payload.role) {
            return res.status(401).json({
                message: 'Invalid access token',
            });
        }
        req.user = {
            id: userId,
            role: String(payload.role),
        };
        next();
    }
    catch {
        return res.status(401).json({
            message: 'Invalid or expired access token',
        });
    }
}
// ======================================================
// POST /auth/login
// ======================================================
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({
            message: 'Email and password are required',
        });
    }
    try {
        const response = await fetch(`http://localhost:3001/users?email=${encodeURIComponent(email)}`);
        if (!response.ok) {
            return res.status(500).json({
                message: 'Could not fetch users',
            });
        }
        const users = await response.json();
        if (users.length === 0) {
            return res.status(401).json({
                message: 'Invalid email or password',
            });
        }
        const user = users[0];
        //
        //
        console.log('USER FROM DB:', user);
        const passwordValid = await bcryptjs_1.default.compare(password, user.password);
        console.log('PASSWORD FROM REQUEST:', password);
        console.log('PASSWORD FROM DB:', user.password);
        console.log('PASSWORD VALID:', passwordValid);
        //
        //
        if (!passwordValid) {
            return res.status(401).json({
                message: 'Invalid email or password',
            });
        }
        if (!user.isActive) {
            return res.status(403).json({
                message: 'User is inactive',
            });
        }
        // Access Token
        const accessToken = jsonwebtoken_1.default.sign({
            sub: user.id,
            role: user.role,
        }, ACCESS_TOKEN_SECRET, {
            expiresIn: '15m',
        });
        // Refresh Token
        const refreshToken = jsonwebtoken_1.default.sign({
            sub: user.id,
        }, REFRESH_TOKEN_SECRET, {
            expiresIn: '7d',
        });
        // HttpOnly Cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        // Remove password from response
        const { password: _, ...safeUser } = user;
        return res.json({
            accessToken,
            user: safeUser,
        });
    }
    catch {
        return res.status(500).json({
            message: 'Login failed',
        });
    }
});
// ======================================================
// POST /auth/refresh
// ======================================================
app.post('/auth/refresh', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(401).json({
            message: 'Refresh token is missing',
        });
    }
    try {
        const payload = jsonwebtoken_1.default.verify(refreshToken, REFRESH_TOKEN_SECRET);
        const userId = Number(payload.sub);
        if (!payload.sub || Number.isNaN(userId)) {
            return res.status(401).json({
                message: 'Invalid refresh token',
            });
        }
        // Check that user still exists
        const response = await fetch(`http://localhost:3001/users/${userId}`);
        if (!response.ok) {
            return res.status(401).json({
                message: 'User not found',
            });
        }
        const user = await response.json();
        if (!user.isActive) {
            return res.status(403).json({
                message: 'User is inactive',
            });
        }
        // New Access Token
        const accessToken = jsonwebtoken_1.default.sign({
            sub: user.id,
            role: user.role,
        }, ACCESS_TOKEN_SECRET, {
            expiresIn: '15m',
        });
        return res.json({
            accessToken,
        });
    }
    catch {
        return res.status(401).json({
            message: 'Invalid or expired refresh token',
        });
    }
});
// ======================================================
// POST /auth/logout
// ======================================================
app.post('/auth/logout', (req, res) => {
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
    });
    return res.json({
        message: 'Logged out successfully',
    });
});
// ======================================================
// GET /auth/me
// ======================================================
app.get('/auth/me', authenticateToken, async (req, res) => {
    try {
        const response = await fetch(`http://localhost:3001/users/${req.user.id}`);
        if (!response.ok) {
            return res.status(404).json({
                message: 'User not found',
            });
        }
        const user = await response.json();
        const { password: _, ...safeUser } = user;
        return res.json({
            user: safeUser,
        });
    }
    catch {
        return res.status(500).json({
            message: 'Could not fetch user',
        });
    }
});
// ======================================================
// POST /auth/register
// ======================================================
app.post('/auth/register', async (req, res) => {
    const { firstName, lastName, email, password, phone } = req.body;
    // --------------------------
    // Validation
    // --------------------------
    if (!firstName || !lastName || !email || !password) {
        return res.status(400).json({
            message: 'Required fields are missing',
        });
    }
    if (password.length < 6) {
        return res.status(400).json({
            message: 'Password must be at least 6 characters',
        });
    }
    try {
        // --------------------------
        // Check duplicate email
        // --------------------------
        const existingResponse = await fetch(`http://localhost:3001/users?email=${encodeURIComponent(email)}`);
        if (!existingResponse.ok) {
            return res.status(500).json({
                message: 'Could not check existing users',
            });
        }
        const existingUsers = await existingResponse.json();
        if (existingUsers.length > 0) {
            return res.status(409).json({
                message: 'Email already exists',
            });
        }
        // --------------------------
        // Hash password
        // --------------------------
        const hashedPassword = await bcryptjs_1.default.hash(password, 10);
        // --------------------------
        // Create user
        // --------------------------
        const newUser = {
            firstName,
            lastName,
            name: `${firstName} ${lastName}`,
            email,
            phone: phone ?? '',
            // Public registration = customer
            role: 'customer',
            isActive: true,
            status: 'active',
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };
        // --------------------------
        // Save to json-server
        // --------------------------
        const response = await fetch('http://localhost:3001/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(newUser),
        });
        if (!response.ok) {
            return res.status(500).json({
                message: 'Could not create user',
            });
        }
        const user = await response.json();
        // --------------------------
        // Remove password
        // --------------------------
        const { password: _, ...safeUser } = user;
        // --------------------------
        // Create tokens
        // --------------------------
        const accessToken = jsonwebtoken_1.default.sign({
            sub: user.id,
            role: user.role,
        }, ACCESS_TOKEN_SECRET, {
            expiresIn: '15m',
        });
        const refreshToken = jsonwebtoken_1.default.sign({
            sub: user.id,
        }, REFRESH_TOKEN_SECRET, {
            expiresIn: '7d',
        });
        // --------------------------
        // Refresh Cookie
        // --------------------------
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        // --------------------------
        // Response
        // --------------------------
        console.log('important', user);
        console.log('REGISTER RESPONSE:', {
            accessToken,
            user: safeUser,
        });
        return res.status(201).json({
            accessToken,
            user: safeUser,
        });
    }
    catch (error) {
        console.error('REGISTER ERROR:', error);
        return res.status(500).json({
            message: 'Registration failed',
        });
    }
});
// ======================================================
// API Proxy → json-server
// ======================================================
app.use('/api', (0, http_proxy_middleware_1.createProxyMiddleware)({
    target: 'http://localhost:3001',
    changeOrigin: true,
    pathRewrite: {
        '^/api': '',
    },
}));
// ======================================================
// Start Server
// ======================================================
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Express running on port ${PORT}`);
});
// app.listen(3000, () => {
//   console.log('Express running on http://localhost:3000');
// });
