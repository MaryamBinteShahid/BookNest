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
    deleteAccount,
    sendPasswordChangeOTP,
    sendAccountDeletionOTP
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

const validatePasswordChange = [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 8 }),
    body('otp').isLength({ min: 6, max: 6 })
];

const validateAccountDeletion = [
    body('otp').isLength({ min: 6, max: 6 })
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

// Password change with OTP verification routes
router.post('/send-password-change-otp', authenticateToken, sendPasswordChangeOTP);
router.put('/profile/password', authenticateToken, validatePasswordChange, updatePassword);

// Account deletion with OTP verification routes
router.post('/send-account-deletion-otp', authenticateToken, sendAccountDeletionOTP);
router.delete('/profile', authenticateToken, validateAccountDeletion, deleteAccount);

module.exports = router;