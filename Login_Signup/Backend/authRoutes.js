const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const {
    signup,
    verifySignupOTP,
    login,
    forgotPassword,
    resetPassword,
    logout,
    getProfile,
    updateName,
    updatePassword,
    deleteAccount
} = require('./authController');
const { authenticateToken } = require('./auth');

// Validation middleware
const validateSignup = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('name').trim().notEmpty()
];

const validateLogin = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
];

// User Stories 1-4 Routes (existing)
router.post('/signup', validateSignup, signup);
router.post('/verify-otp', verifySignupOTP);
router.post('/login', validateLogin, login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/logout', authenticateToken, logout);

// User Stories 5-8 Routes (new)
router.get('/profile', authenticateToken, getProfile);
router.put('/profile/name', authenticateToken, updateName);
router.put('/profile/password', authenticateToken, updatePassword);
router.delete('/profile', authenticateToken, deleteAccount);

module.exports = router;