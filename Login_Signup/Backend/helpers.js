const crypto = require('crypto');

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateUUID() {
    return crypto.randomUUID();
}

function validatePassword(password) {
    if (password.length < 8) {
        return { valid: false, message: 'Password must be at least 8 characters long' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one digit' };
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one special character' };
    }
    return { valid: true };
}

function validateMobile(mobile) {
    
    const cleanMobile = mobile.replace(/\D/g, '');
    
    // Check if it's a valid length (typically 10-15 digits)
    if (cleanMobile.length < 10 || cleanMobile.length > 15) {
        return { valid: false, message: 'Mobile number must be between 10-15 digits' };
    }
    
    // Check if it contains only digits
    if (!/^\d+$/.test(cleanMobile)) {
        return { valid: false, message: 'Mobile number must contain only digits' };
    }
    
    return { valid: true };
}

module.exports = {
    generateOTP,
    generateUUID,
    validatePassword,
    validateMobile
};