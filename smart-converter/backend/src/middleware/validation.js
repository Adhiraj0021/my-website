const Joi = require('joi');

// Validation schemas
const schemas = {
  // User registration validation
  register: Joi.object({
    name: Joi.string()
      .min(2)
      .max(50)
      .required()
      .messages({
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 50 characters',
        'any.required': 'Name is required',
        'string.empty': 'Name cannot be empty'
      }),
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty'
      }),
    password: Joi.string()
      .min(6)
      .pattern(/^(?=.*[A-Z])(?=.*\d)/)
      .required()
      .messages({
        'string.min': 'Password must be at least 6 characters long',
        'string.pattern.base': 'Password must contain at least 1 uppercase letter and 1 number',
        'any.required': 'Password is required',
        'string.empty': 'Password cannot be empty'
      })
  }),

  // User login validation
  login: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty'
      }),
    password: Joi.string()
      .required()
      .messages({
        'any.required': 'Password is required',
        'string.empty': 'Password cannot be empty'
      })
  }),

  // User profile update validation
  updateProfile: Joi.object({
    name: Joi.string()
      .min(2)
      .max(50)
      .optional()
      .messages({
        'string.min': 'Name must be at least 2 characters long',
        'string.max': 'Name cannot exceed 50 characters'
      }),
    phone: Joi.string()
      .pattern(/^[\+]?[1-9][\d]{0,15}$/)
      .optional()
      .messages({
        'string.pattern.base': 'Please provide a valid phone number'
      }),
    address: Joi.string()
      .max(200)
      .optional()
      .messages({
        'string.max': 'Address cannot exceed 200 characters'
      })
  }),

  // Conversion validation
  conversion: Joi.object({
    fromUnit: Joi.string()
      .required()
      .messages({
        'any.required': 'From unit is required',
        'string.empty': 'From unit cannot be empty'
      }),
    toUnit: Joi.string()
      .required()
      .messages({
        'any.required': 'To unit is required',
        'string.empty': 'To unit cannot be empty'
      }),
    fromValue: Joi.number()
      .positive()
      .required()
      .messages({
        'number.base': 'From value must be a number',
        'number.positive': 'From value must be positive',
        'any.required': 'From value is required'
      }),
    conversionType: Joi.string()
      .valid('length', 'weight', 'temperature', 'area', 'volume', 'currency')
      .required()
      .messages({
        'any.only': 'Conversion type must be one of: length, weight, temperature, area, volume, currency',
        'any.required': 'Conversion type is required'
      })
  }),

  // Rating validation
  rating: Joi.object({
    tool: Joi.string()
      .required()
      .messages({
        'any.required': 'Tool name is required',
        'string.empty': 'Tool name cannot be empty'
      }),
    rating: Joi.number()
      .min(1)
      .max(5)
      .integer()
      .required()
      .messages({
        'number.base': 'Rating must be a number',
        'number.min': 'Rating must be at least 1',
        'number.max': 'Rating cannot exceed 5',
        'number.integer': 'Rating must be a whole number',
        'any.required': 'Rating is required'
      }),
    comment: Joi.string()
      .max(500)
      .optional()
      .messages({
        'string.max': 'Comment cannot exceed 500 characters'
      })
  }),

  // Bug report validation
  bugReport: Joi.object({
    type: Joi.string()
      .valid('bug', 'feature')
      .required()
      .messages({
        'any.only': 'Type must be either "bug" or "feature"',
        'any.required': 'Type is required',
        'string.empty': 'Type cannot be empty'
      }),
    message: Joi.string()
      .min(10)
      .max(1000)
      .required()
      .messages({
        'string.min': 'Message must be at least 10 characters long',
        'string.max': 'Message cannot exceed 1000 characters',
        'string.empty': 'Message cannot be empty',
        'any.required': 'Message is required'
      })
  }),

  // OTP validation
  sendOtp: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty'
      })
  }),

  verifyOtp: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty'
      }),
    otp: Joi.string()
      .length(6)
      .pattern(/^\d{6}$/)
      .required()
      .messages({
        'string.length': 'OTP must be exactly 6 digits',
        'string.pattern.base': 'OTP must contain only digits',
        'any.required': 'OTP is required',
        'string.empty': 'OTP cannot be empty'
      })
  }),

  // Password reset validation
  forgotPassword: Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required',
        'string.empty': 'Email cannot be empty'
      })
  }),

  resetPassword: Joi.object({
    token: Joi.string()
      .required()
      .messages({
        'any.required': 'Reset token is required',
        'string.empty': 'Reset token cannot be empty'
      }),
    password: Joi.string()
      .min(6)
      .pattern(/^(?=.*[A-Z])(?=.*\d)/)
      .required()
      .messages({
        'string.min': 'Password must be at least 6 characters long',
        'string.pattern.base': 'Password must contain at least 1 uppercase letter and 1 number',
        'any.required': 'Password is required',
        'string.empty': 'Password cannot be empty'
      })
  })
};

// Validation middleware function
const validate = (schemaName) => {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) {
      return res.status(500).json({ 
        success: false, 
        message: 'Validation schema not found' 
      });
    }

    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorMessages = error.details.map(detail => detail.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errorMessages
      });
    }

    // Replace req.body with validated data
    req.body = value;
    next();
  };
};

module.exports = {
  validate,
  schemas
}; 