import express from 'express';
import { register_user, login_user, logout_user } from '../controller/auth.controller.js';
import { authMiddleware } from '../middleware/auth.middleware.js';
import { validateRegisterInput, validateLoginInput } from '../middleware/validation.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const Router = express.Router();

Router.post('/register', authLimiter, validateRegisterInput, register_user)
Router.post('/login', authLimiter, validateLoginInput, login_user);
Router.post('/logout', logout_user);
Router.get('/me', authMiddleware, (req, res) => {
    res.status(200).json(req.user)
})

export default Router;
