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
    sendAccountDeletionOTP,
    // New functions for email verification
    checkEmailVerification,
    resendVerificationOTP,
    verifyEmailOTP,
    // New function for OTP verification only
    verifyResetOTP  // ADD THIS LINE
} = require('./authController');
const { authenticateToken } = require('./auth');

// Validation middleware
const validateSignup = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('name').trim().notEmpty(),
    body('mobile')
        .isMobilePhone('any')
        .withMessage('Please provide a valid mobile number')
        .notEmpty()
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

// ========== NEW ROUTES FOR EMAIL VERIFICATION FEATURE ==========

// Check email verification status
router.post('/check-email-verification', checkEmailVerification);

// Resend verification OTP for existing unverified users
router.post('/resend-verification-otp', resendVerificationOTP);

// Verify email OTP for existing users
router.post('/verify-email-otp', verifyEmailOTP);

// OTP verification for password reset (without resetting password)
router.post('/verify-reset-otp', verifyResetOTP);  // ADD THIS ROUTE

module.exports = router;