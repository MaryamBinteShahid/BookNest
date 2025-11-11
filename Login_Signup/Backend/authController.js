// ============================================
// UPDATED: authController.js
// ============================================
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getConnection } = require('./database');
const { generateOTP, generateUUID, validatePassword } = require('./helpers');
const { sendOTPEmail } = require('./emailService');

// ========== EXISTING FUNCTIONS (User Stories 1-4) ==========

async function signup(req, res) {
    let connection;
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and password are required'
            });
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        connection = await getConnection();

        const checkUserQuery = 'SELECT user_id FROM users WHERE email = :email';
        const result = await connection.execute(checkUserQuery, [email]);

        if (result.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        const otp = generateOTP();
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        const insertOTPQuery = `
            INSERT INTO otps (otp_id, email, otp_code, otp_type, expires_at)
            VALUES (:otpId, :email, :otp, :type, :expiresAt)
        `;
        await connection.execute(insertOTPQuery, {
            otpId,
            email,
            otp,
            type: 'signup',
            expiresAt
        });

        const userId = generateUUID();
        const passwordHash = await bcrypt.hash(password, 10);

        const insertUserQuery = `
            INSERT INTO users (user_id, name, email, password_hash, is_verified)
            VALUES (:userId, :name, :email, :passwordHash, 0)
        `;
        await connection.execute(insertUserQuery, {
            userId,
            name,
            email,
            passwordHash
        });

        await sendOTPEmail(email, otp, 'signup');

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email. Please verify to complete registration.'
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during signup'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

async function verifySignupOTP(req, res) {
    let connection;
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        connection = await getConnection();

        const checkOTPQuery = `
            SELECT otp_id, expires_at, is_used 
            FROM otps 
            WHERE email = :email 
            AND otp_code = :otp 
            AND otp_type = 'signup'
            ORDER BY created_at DESC
            FETCH FIRST 1 ROWS ONLY
        `;
        const otpResult = await connection.execute(checkOTPQuery, [email, otp]);

        if (otpResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        const otpData = otpResult.rows[0];

        if (otpData.IS_USED === 1) {
            return res.status(400).json({
                success: false,
                message: 'OTP already used'
            });
        }

        if (new Date(otpData.EXPIRES_AT) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        const updateOTPQuery = 'UPDATE otps SET is_used = 1 WHERE otp_id = :otpId';
        await connection.execute(updateOTPQuery, [otpData.OTP_ID]);

        const updateUserQuery = 'UPDATE users SET is_verified = 1 WHERE email = :email';
        await connection.execute(updateUserQuery, [email]);

        res.status(200).json({
            success: true,
            message: 'Email verified successfully. You can now login.'
        });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during OTP verification'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

async function login(req, res) {
    let connection;
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        connection = await getConnection();

        const getUserQuery = `
            SELECT user_id, name, email, password_hash, is_verified, role 
            FROM users 
            WHERE email = :email
        `;
        const result = await connection.execute(getUserQuery, [email]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const user = result.rows[0];

        if (user.IS_VERIFIED === 0) {
            return res.status(403).json({
                success: false,
                message: 'Account not verified. Please verify your email with OTP.'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.PASSWORD_HASH);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign(
            {
                userId: user.USER_ID,
                email: user.EMAIL,
                role: user.ROLE
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                userId: user.USER_ID,
                name: user.NAME,
                email: user.EMAIL,
                role: user.ROLE
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

async function forgotPassword(req, res) {
    let connection;
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        connection = await getConnection();

        const checkUserQuery = 'SELECT user_id FROM users WHERE email = :email';
        const result = await connection.execute(checkUserQuery, [email]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Email not registered'
            });
        }

        const otp = generateOTP();
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        const insertOTPQuery = `
            INSERT INTO otps (otp_id, email, otp_code, otp_type, expires_at)
            VALUES (:otpId, :email, :otp, :type, :expiresAt)
        `;
        await connection.execute(insertOTPQuery, {
            otpId,
            email,
            otp,
            type: 'reset',
            expiresAt
        });

        await sendOTPEmail(email, otp, 'reset');

        res.status(200).json({
            success: true,
            message: 'Password reset OTP sent to your email'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during password reset request'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

async function resetPassword(req, res) {
    let connection;
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Email, OTP, and new password are required'
            });
        }

        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        connection = await getConnection();

        const checkOTPQuery = `
            SELECT otp_id, expires_at, is_used 
            FROM otps 
            WHERE email = :email 
            AND otp_code = :otp 
            AND otp_type = 'reset'
            ORDER BY created_at DESC
            FETCH FIRST 1 ROWS ONLY
        `;
        const otpResult = await connection.execute(checkOTPQuery, [email, otp]);

        if (otpResult.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        const otpData = otpResult.rows[0];

        if (otpData.IS_USED === 1) {
            return res.status(400).json({
                success: false,
                message: 'OTP already used'
            });
        }

        if (new Date(otpData.EXPIRES_AT) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        const getUserQuery = 'SELECT password_hash FROM users WHERE email = :email';
        const userResult = await connection.execute(getUserQuery, [email]);
        
        if (userResult.rows.length > 0) {
            const isSamePassword = await bcrypt.compare(newPassword, userResult.rows[0].PASSWORD_HASH);
            if (isSamePassword) {
                return res.status(400).json({
                    success: false,
                    message: 'New password cannot be the same as old password'
                });
            }
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);

        const updatePasswordQuery = `
            UPDATE users 
            SET password_hash = :passwordHash, updated_at = CURRENT_TIMESTAMP 
            WHERE email = :email
        `;
        await connection.execute(updatePasswordQuery, {
            passwordHash,
            email
        });

        const updateOTPQuery = 'UPDATE otps SET is_used = 1 WHERE otp_id = :otpId';
        await connection.execute(updateOTPQuery, [otpData.OTP_ID]);

        res.status(200).json({
            success: true,
            message: 'Password reset successful. You can now login with your new password.'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during password reset'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

async function logout(req, res) {
    res.status(200).json({
        success: true,
        message: 'Logged out successfully'
    });
}

// ========== NEW FUNCTIONS (User Stories 5-8) ==========

// User Story 5 & 6: Get Profile
async function getProfile(req, res) {
    let connection;
    try {
        const userId = req.user.userId; // From JWT token

        connection = await getConnection();

        const getUserQuery = `
            SELECT user_id, name, email, role, created_at, updated_at
            FROM users 
            WHERE user_id = :userId
        `;
        const result = await connection.execute(getUserQuery, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const user = result.rows[0];

        res.status(200).json({
            success: true,
            user: {
                userId: user.USER_ID,
                name: user.NAME,
                email: user.EMAIL,
                role: user.ROLE,
                createdAt: user.CREATED_AT,
                updatedAt: user.UPDATED_AT
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching profile'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// User Story 6: Update Name
async function updateName(req, res) {
    let connection;
    try {
        const userId = req.user.userId;
        const { name } = req.body;

        if (!name || name.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Name cannot be empty'
            });
        }

        connection = await getConnection();

        const updateNameQuery = `
            UPDATE users 
            SET name = :name, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = :userId
        `;
        const result = await connection.execute(updateNameQuery, {
            name: name.trim(),
            userId
        });

        if (result.rowsAffected === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Name updated successfully',
            name: name.trim()
        });

    } catch (error) {
        console.error('Update name error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error while updating name'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// User Story 7: Update Password
async function updatePassword(req, res) {
    let connection;
    try {
        const userId = req.user.userId;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        connection = await getConnection();

        const getUserQuery = 'SELECT password_hash FROM users WHERE user_id = :userId';
        const result = await connection.execute(getUserQuery, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const user = result.rows[0];

        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.PASSWORD_HASH);
        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        const isSamePassword = await bcrypt.compare(newPassword, user.PASSWORD_HASH);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password cannot be the same as current password'
            });
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);

        const updatePasswordQuery = `
            UPDATE users 
            SET password_hash = :passwordHash, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = :userId
        `;
        await connection.execute(updatePasswordQuery, {
            passwordHash,
            userId
        });

        res.status(200).json({
            success: true,
            message: 'Password updated successfully'
        });

    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error while updating password'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// User Story 8: Delete Account
async function deleteAccount(req, res) {
    let connection;
    try {
        const userId = req.user.userId;

        connection = await getConnection();

        // Check if user exists
        const checkUserQuery = 'SELECT user_id FROM users WHERE user_id = :userId';
        const checkResult = await connection.execute(checkUserQuery, [userId]);

        if (checkResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Delete user's OTPs first (foreign key constraint)
        const deleteOTPsQuery = 'DELETE FROM otps WHERE email = (SELECT email FROM users WHERE user_id = :userId)';
        await connection.execute(deleteOTPsQuery, [userId]);

        // Delete user account
        const deleteUserQuery = 'DELETE FROM users WHERE user_id = :userId';
        const result = await connection.execute(deleteUserQuery, [userId]);

        if (result.rowsAffected === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Account deleted successfully'
        });

    } catch (error) {
        console.error('Delete account error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error while deleting account'
        });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

module.exports = {
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
};