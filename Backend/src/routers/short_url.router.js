import express from 'express';
import { createShortUrl } from '../controller/short_url.controller.js';
import { validateUrlInput } from '../middleware/validation.js';
import { createUrlLimiter } from '../middleware/rateLimiter.js';

const router = express.Router(); 
router.post("/", createUrlLimiter, validateUrlInput, createShortUrl);
export default router;
