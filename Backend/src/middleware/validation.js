import Joi from 'joi';
import DOMPurify from 'isomorphic-dompurify';

// URL validation schema
const urlSchema = Joi.object({
  url: Joi.string()
    .uri({ scheme: ['http', 'https'] })
    .required()
    .max(2048)
    .messages({
      'string.uri': 'Please provide a valid URL starting with http:// or https://',
      'string.max': 'URL cannot exceed 2048 characters',
      'any.required': 'URL is required'
    }),
  slug: Joi.string()
    .alphanum()
    .min(3)
    .max(50)
    .optional()
    .messages({
      'string.alphanum': 'Custom slug can only contain letters and numbers',
      'string.min': 'Custom slug must be at least 3 characters',
      'string.max': 'Custom slug cannot exceed 50 characters'
    })
});

// User registration validation schema
const registerSchema = Joi.object({
  name: Joi.string()
    .min(2)
    .max(50)
    .pattern(/^[a-zA-Z\s]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Name can only contain letters and spaces',
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name cannot exceed 50 characters'
    }),
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address'
    }),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'string.min': 'Password must be at least 8 characters long',
      'string.max': 'Password cannot exceed 128 characters'
    })
});

// Login validation schema
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// Validation middleware
export const validateUrlInput = (req, res, next) => {
  const { error, value } = urlSchema.validate(req.body, { abortEarly: false });
  
  if (error) {
    const errorMessages = error.details.map(detail => detail.message);
    return res.status(400).json({
      success: false,
      message: 'Invalid input data',
      errors: errorMessages
    });
  }
  
  // Sanitize inputs
  req.body.url = DOMPurify.sanitize(value.url.trim());
  if (value.slug) {
    req.body.slug = DOMPurify.sanitize(value.slug.trim().toLowerCase());
  }
  
  next();
};

export const validateRegisterInput = (req, res, next) => {
  const { error, value } = registerSchema.validate(req.body, { abortEarly: false });
  
  if (error) {
    const errorMessages = error.details.map(detail => detail.message);
    return res.status(400).json({
      success: false,
      message: 'Invalid registration data',
      errors: errorMessages
    });
  }
  
  // Sanitize inputs
  req.body.name = DOMPurify.sanitize(value.name.trim());
  req.body.email = value.email.toLowerCase().trim();
  req.body.password = value.password; // Don't sanitize password
  
  next();
};

export const validateLoginInput = (req, res, next) => {
  const { error, value } = loginSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Invalid login data'
    });
  }
  
  req.body.email = value.email.toLowerCase().trim();
  next();
};
