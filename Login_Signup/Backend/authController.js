// ============================================
// UPDATED: authController.js for Supabase
// ============================================
/*const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { supabase } = require('./database'); // Changed to supabase
const { generateOTP, generateUUID, validatePassword, validateMobile } = require('./helpers');
const { sendOTPEmail } = require('./emailService');

// ========== EXISTING FUNCTIONS (User Stories 1-4) ==========

async function signup(req, res) {
    try {
        const { name, email, password, mobile } = req.body;

        if (!name || !email || !password || !mobile) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, mobile number and password are required'
            });
        }
        
        const mobileValidation = validateMobile(mobile);
        if (!mobileValidation.valid) {
            return res.status(400).json({
                success: false,
                message: mobileValidation.message
            });
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        // Check if user already exists - Supabase version
        const { data: existingUser, error: userError } = await supabase
            .from('users')
            .select('user_id')
            .eq('email', email)
            .single();

        // Check if mobile already exists - Supabase version
        const { data: existingUserByMobile, error: mobileError } = await supabase
            .from('users')
            .select('user_id')
            .eq('mobile', mobile)
            .single();    

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }
        
        if (existingUserByMobile) {
            return res.status(409).json({
            success: false,
            message: 'Mobile number already registered'
        });
}
        const otp = generateOTP();
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        const userId = generateUUID();
        const passwordHash = await bcrypt.hash(password, 10);

        // Insert user - Supabase version
        const { error: userInsertError } = await supabase
            .from('users')
            .insert({
                user_id: userId,
                name: name,
                email: email,
                mobile: mobile,
                password_hash: passwordHash,
                is_verified: false,
                role: 'user',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });

        if (userInsertError) {
            console.error('User insert error:', userInsertError);
            
            // Handle unique constraint violation for username
            if (userInsertError.code === '23505') {
                // PostgreSQL unique violation code
                const errorMessage = userInsertError.message || '';
                
                // Check if it's a username constraint violation
                if (errorMessage.includes('name') || errorMessage.includes('username') || 
                    errorMessage.includes('users_name_key') || errorMessage.includes('unique_username')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already taken'
                    });
                }
                
                // If we can't determine the specific constraint, return generic message
                return res.status(409).json({
                    success: false,
                    message: 'Username or email already exists'
                });
            }
            
            // For other database errors, throw to be caught by the general error handler
            throw userInsertError;
        }

        // Insert OTP - Supabase version
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                otp_id: otpId,
                email: email,
                otp_code: otp,
                otp_type: 'signup',
                is_used: false,
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

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
    }
}

/*async function verifySignupOTP(req, res) {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Find OTP - Supabase version
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', otp)
            .eq('otp_type', 'signup')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        // Mark OTP as used - Supabase version
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Verify user - Supabase version
        await supabase
            .from('users')
            .update({ 
                is_verified: true,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

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
    }
}

async function verifySignupOTP(req, res) {
    try {
        const { email, otp } = req.body;

        console.log('🔐 OTP Verification Attempt:', { email, otp });

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Clean the OTP (remove spaces)
        const cleanOTP = otp.toString().trim();

        // Query without .single() to avoid errors
        const { data: otpRecords, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', cleanOTP)
            .eq('otp_type', 'signup')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1);

        console.log('📊 OTP Query Results:', { 
            recordsCount: otpRecords ? otpRecords.length : 0,
            error: otpError 
        });

        if (otpError) {
            console.error('❌ OTP Query Error:', otpError);
        }

        const otpData = otpRecords && otpRecords.length > 0 ? otpRecords[0] : null;

        if (!otpData) {
            console.log('❌ No valid OTP found');
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        console.log('⏰ OTP Time Check:', {
            expires_at: otpData.expires_at,
            current_time: new Date().toISOString(),
            is_expired: new Date(otpData.expires_at) < new Date()
        });

        // Check expiry with 1-minute buffer
        if (new Date(otpData.expires_at) < new Date(Date.now() - 60000)) {
            console.log('❌ OTP Expired');
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        console.log('✅ OTP Valid - Proceeding with verification');

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Verify user
        await supabase
            .from('users')
            .update({ 
                is_verified: true,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

        console.log('🎉 User verified successfully');

        res.status(200).json({
            success: true,
            message: 'Email verified successfully. You can now login.'
        });

    } catch (error) {
        console.error('💥 OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during OTP verification'
        });
    }
}
async function login(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Get user - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (userError || !user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        if (!user.is_verified) {
            return res.status(403).json({
                success: false,
                message: 'Account not verified. Please verify your email with OTP.'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign(
            {
                userId: user.user_id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                userId: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
}

async function forgotPassword(req, res) {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // Check if user exists - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id')
            .eq('email', email)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Email not registered'
            });
        }

        const otp = generateOTP();
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP - Supabase version
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                otp_id: otpId,
                email: email,
                otp_code: otp,
                otp_type: 'reset',
                is_used: false,
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

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
    }
}

async function resetPassword(req, res) {
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

        // Find OTP - Supabase version
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', otp)
            .eq('otp_type', 'reset')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        // Get user to check old password - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('password_hash')
            .eq('email', email)
            .single();

        if (user) {
            const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);
            if (isSamePassword) {
                return res.status(400).json({
                    success: false,
                    message: 'New password cannot be the same as old password'
                });
            }
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);

        // Update password - Supabase version
        await supabase
            .from('users')
            .update({ 
                password_hash: passwordHash,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

        // Mark OTP as used - Supabase version
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

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
    try {
        const userId = req.user.userId;

        // Get user profile - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id, name, email, mobile, role, created_at, updated_at')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            user: {
                userId: user.user_id,
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                role: user.role,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching profile'
        });
    }
}

// User Story 6: Update Name
async function updateName(req, res) {
    try {
        const userId = req.user.userId;
        const { name } = req.body;

        if (!name || name.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Name cannot be empty'
            });
        }

        const trimmedName = name.trim();

        // Check if the new name is the same as current name
        const { data: currentUser, error: currentUserError } = await supabase
            .from('users')
            .select('name')
            .eq('user_id', userId)
            .single();

        if (currentUserError || !currentUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (currentUser.name === trimmedName) {
            return res.status(400).json({
                success: false,
                message: 'New name cannot be the same as current name'
            });
        }

        // Check if username already exists (excluding current user)
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('user_id')
            .eq('name', trimmedName)
            .neq('user_id', userId) // Exclude current user
            .single();

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Username already taken'
            });
        }

        // Update name - Supabase version
        const { data, error } = await supabase
            .from('users')
            .update({ 
                name: trimmedName,
                updated_at: new Date().toISOString()
            })
            .eq('user_id', userId)
            .select();

        if (error) {
            console.error('Update name error:', error);
            
            // Handle unique constraint violation for username
            if (error.code === '23505') {
                // PostgreSQL unique violation code
                const errorMessage = error.message || '';
                
                // Check if it's a username constraint violation
                if (errorMessage.includes('name') || errorMessage.includes('username') || 
                    errorMessage.includes('users_name_key') || errorMessage.includes('unique_username')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already taken'
                    });
                }
            }
            
            return res.status(500).json({
                success: false,
                message: 'Database error while updating name'
            });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Name updated successfully',
            name: trimmedName
        });

    } catch (error) {
        console.error('Update name error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error while updating name'
        });
    }
}

// User Story 7: Update Password with OTP Verification
async function updatePassword(req, res) {
    try {
        const userId = req.user.userId;
        const { currentPassword, newPassword, otp } = req.body;

        if (!currentPassword || !newPassword || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Current password, new password, and OTP are required'
            });
        }

        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        // Get user data including email for OTP verification
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id, email, password_hash')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password first
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Check if new password is same as current
        const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password cannot be the same as current password'
            });
        }

        // Verify OTP for password change
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', user.email)
            .eq('otp_code', otp)
            .eq('otp_type', 'password_change')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Update password
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await supabase
            .from('users')
            .update({ 
                password_hash: passwordHash,
                updated_at: new Date().toISOString()
            })
            .eq('user_id', userId);

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
    }
}

// New function: Send OTP for password change
async function sendPasswordChangeOTP(req, res) {
    try {
        const userId = req.user.userId;

        // Get user email
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP for password change
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                email: user.email,
                otp_code: otp,
                otp_type: 'password_change',
                is_used: false,
                expires_at: expiresAt.toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        // Send OTP email
        await sendOTPEmail(user.email, otp, 'password_change');

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email for password change verification'
        });

    } catch (error) {
        console.error('Send password change OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while sending OTP'
        });
    }
}

// User Story 8: Delete Account with OTP Verification
async function deleteAccount(req, res) {
    try {
        const userId = req.user.userId;
        const { otp } = req.body;

        if (!otp) {
            return res.status(400).json({
                success: false,
                message: 'OTP is required for account deletion'
            });
        }

        // Get user email first
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify OTP for account deletion
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', user.email)
            .eq('otp_code', otp)
            .eq('otp_type', 'account_deletion')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Delete user's OTPs first
        await supabase
            .from('otps')
            .delete()
            .eq('email', user.email);

        // Delete user account
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('user_id', userId);

        if (deleteError) {
            throw deleteError;
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
    }
}

// New function: Send OTP for account deletion
async function sendAccountDeletionOTP(req, res) {
    try {
        const userId = req.user.userId;

        // Get user email
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP for account deletion
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                email: user.email,
                otp_code: otp,
                otp_type: 'account_deletion',
                is_used: false,
                expires_at: expiresAt.toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        // Send OTP email
        await sendOTPEmail(user.email, otp, 'account_deletion');

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email for account deletion verification'
        });

    } catch (error) {
        console.error('Send account deletion OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while sending OTP'
        });
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
    deleteAccount,
    sendPasswordChangeOTP,   
    sendAccountDeletionOTP 
};*/


// ============================================
// UPDATED: authController.js for Supabase
// ============================================
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { supabase } = require('./database'); 
const { generateOTP, generateUUID, validatePassword, validateMobile } = require('./helpers');
const { sendOTPEmail } = require('./emailService');

// ========== EXISTING FUNCTIONS (User Stories 1-4) ==========

async function signup(req, res) {
    try {
        const { name, email, password, mobile } = req.body;

        if (!name || !email || !password || !mobile) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, mobile number and password are required'
            });
        }
        
        const mobileValidation = validateMobile(mobile);
        if (!mobileValidation.valid) {
            return res.status(400).json({
                success: false,
                message: mobileValidation.message
            });
        }

        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        // Check if user already exists - Supabase version
        const { data: existingUser, error: userError } = await supabase
            .from('users')
            .select('user_id')
            .eq('email', email)
            .single();

        // Check if mobile already exists - Supabase version
        const { data: existingUserByMobile, error: mobileError } = await supabase
            .from('users')
            .select('user_id')
            .eq('mobile', mobile)
            .single();    

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }
        
        if (existingUserByMobile) {
            return res.status(409).json({
            success: false,
            message: 'Mobile number already registered'
        });
        }
        
        // **FIX 1A: Get OTP and clean it before storing**
        const otp = generateOTP();
        const cleanedOTP = otp.toString().trim(); // Ensure no leading/trailing spaces are saved
        
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        const userId = generateUUID();
        const passwordHash = await bcrypt.hash(password, 10);

        // Insert user - Supabase version
        const { error: userInsertError } = await supabase
            .from('users')
            .insert({
                user_id: userId,
                name: name,
                email: email,
                mobile: mobile,
                password_hash: passwordHash,
                is_verified: false,
                role: 'user',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });

        if (userInsertError) {
            console.error('User insert error:', userInsertError);
            
            // Handle unique constraint violation for username
            if (userInsertError.code === '23505') {
                // PostgreSQL unique violation code
                const errorMessage = userInsertError.message || '';
                
                // Check if it's a username constraint violation
                if (errorMessage.includes('name') || errorMessage.includes('username') || 
                    errorMessage.includes('users_name_key') || errorMessage.includes('unique_username')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already taken'
                    });
                }
                
                // If we can't determine the specific constraint, return generic message
                return res.status(409).json({
                    success: false,
                    message: 'Username or email already exists'
                });
            }
            
            // For other database errors, throw to be caught by the general error handler
            throw userInsertError;
        }

        // Insert OTP - Supabase version
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                otp_id: otpId,
                email: email,
                otp_code: cleanedOTP, // **FIX 1B: Use the cleaned version here**
                otp_type: 'signup',
                is_used: false,
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        await sendOTPEmail(email, otp, 'signup'); // Send the original, potentially non-trimmed OTP to the user's email client

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
    }
}

async function verifySignupOTP(req, res) {
    try {
        const { email, otp } = req.body;

        console.log('🔐 OTP Verification Attempt:', { email, otp });

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Clean the OTP (remove spaces) - This is correct and keeps the client input clean
        const cleanOTP = otp.toString().trim();

        // Query without .single() to avoid errors
        const { data: otpRecords, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', cleanOTP)
            .eq('otp_type', 'signup')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1);

        console.log('📊 OTP Query Results:', { 
            recordsCount: otpRecords ? otpRecords.length : 0,
            error: otpError 
        });

        if (otpError) {
            console.error('❌ OTP Query Error:', otpError);
        }

        const otpData = otpRecords && otpRecords.length > 0 ? otpRecords[0] : null;

        if (!otpData) {
            console.log('❌ No valid OTP found');
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // **FIX 2: Simplified Expiry Check**
        console.log('⏰ OTP Time Check:', {
            expires_at: otpData.expires_at,
            current_time: new Date().toISOString(),
            is_expired: new Date(otpData.expires_at) < new Date()
        });

        // Check expiry: is the expiry date (from DB) earlier than the current date?
        if (new Date(otpData.expires_at) < new Date()) {
            console.log('❌ OTP Expired');
            
            // OPTIONAL: Mark expired OTP as used to prevent future attempts, although the main query already filters by expires_at
            // await supabase.from('otps').update({ is_used: true }).eq('otp_id', otpData.otp_id);
            
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        console.log('✅ OTP Valid - Proceeding with verification');

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Verify user
        await supabase
            .from('users')
            .update({ 
                is_verified: true,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

        console.log('🎉 User verified successfully');

        res.status(200).json({
            success: true,
            message: 'Email verified successfully. You can now login.'
        });

    } catch (error) {
        console.error('💥 OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during OTP verification'
        });
    }
}

// ... (rest of the functions remain the same) ...

async function login(req, res) {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Get user - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (userError || !user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        if (!user.is_verified) {
            return res.status(403).json({
                success: false,
                message: 'Account not verified. Please verify your email with OTP.'
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign(
            {
                userId: user.user_id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                userId: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
}

async function forgotPassword(req, res) {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // Check if user exists - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id')
            .eq('email', email)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Email not registered'
            });
        }

        // **FIX 1A (Applied to forgotPassword): Get OTP and clean it before storing**
        const otp = generateOTP();
        const cleanedOTP = otp.toString().trim(); // Ensure no leading/trailing spaces are saved

        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP - Supabase version
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                otp_id: otpId,
                email: email,
                otp_code: cleanedOTP, // **FIX 1B: Use the cleaned version here**
                otp_type: 'reset',
                is_used: false,
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

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
    }
}

async function resetPassword(req, res) {
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
        
        // Clean the OTP (remove spaces)
        const cleanOTP = otp.toString().trim();

        // Find OTP - Supabase version
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', cleanOTP) // **Using cleanOTP for query**
            .eq('otp_type', 'reset')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) { // Simplified expiry check
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        // Get user to check old password - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('password_hash')
            .eq('email', email)
            .single();

        if (user) {
            const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);
            if (isSamePassword) {
                return res.status(400).json({
                    success: false,
                    message: 'New password cannot be the same as old password'
                });
            }
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);

        // Update password - Supabase version
        await supabase
            .from('users')
            .update({ 
                password_hash: passwordHash,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

        // Mark OTP as used - Supabase version
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

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
    try {
        const userId = req.user.userId;

        // Get user profile - Supabase version
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id, name, email, mobile, role, created_at, updated_at')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            user: {
                userId: user.user_id,
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                role: user.role,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }
        });

    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching profile'
        });
    }
}

// User Story 6: Update Name
async function updateName(req, res) {
    try {
        const userId = req.user.userId;
        const { name } = req.body;

        if (!name || name.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Name cannot be empty'
            });
        }

        const trimmedName = name.trim();

        // Check if the new name is the same as current name
        const { data: currentUser, error: currentUserError } = await supabase
            .from('users')
            .select('name')
            .eq('user_id', userId)
            .single();

        if (currentUserError || !currentUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (currentUser.name === trimmedName) {
            return res.status(400).json({
                success: false,
                message: 'New name cannot be the same as current name'
            });
        }

        // Check if username already exists (excluding current user)
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('user_id')
            .eq('name', trimmedName)
            .neq('user_id', userId) // Exclude current user
            .single();

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Username already taken'
            });
        }

        // Update name - Supabase version
        const { data, error } = await supabase
            .from('users')
            .update({ 
                name: trimmedName,
                updated_at: new Date().toISOString()
            })
            .eq('user_id', userId)
            .select();

        if (error) {
            console.error('Update name error:', error);
            
            // Handle unique constraint violation for username
            if (error.code === '23505') {
                // PostgreSQL unique violation code
                const errorMessage = error.message || '';
                
                // Check if it's a username constraint violation
                if (errorMessage.includes('name') || errorMessage.includes('username') || 
                    errorMessage.includes('users_name_key') || errorMessage.includes('unique_username')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already taken'
                    });
                }
            }
            
            return res.status(500).json({
                success: false,
                message: 'Database error while updating name'
            });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Name updated successfully',
            name: trimmedName
        });

    } catch (error) {
        console.error('Update name error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error while updating name'
        });
    }
}

// User Story 7: Update Password with OTP Verification
async function updatePassword(req, res) {
    try {
        const userId = req.user.userId;
        const { currentPassword, newPassword, otp } = req.body;

        if (!currentPassword || !newPassword || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Current password, new password, and OTP are required'
            });
        }

        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                message: passwordValidation.message
            });
        }

        // Get user data including email for OTP verification
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id, email, password_hash')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password first
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isCurrentPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Check if new password is same as current
        const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password cannot be the same as current password'
            });
        }
        
        // Clean the OTP (remove spaces)
        const cleanOTP = otp.toString().trim();

        // Verify OTP for password change
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', user.email)
            .eq('otp_code', cleanOTP) // **Using cleanOTP for query**
            .eq('otp_type', 'password_change')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) { // Simplified expiry check
            return res.status(400).json({
                success: false,
                message: 'OTP has expired'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Update password
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await supabase
            .from('users')
            .update({ 
                password_hash: passwordHash,
                updated_at: new Date().toISOString()
            })
            .eq('user_id', userId);

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
    }
}

// New function: Send OTP for password change
async function sendPasswordChangeOTP(req, res) {
    try {
        const userId = req.user.userId;

        // Get user email
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // **FIX 1A (Applied to sendPasswordChangeOTP): Get OTP and clean it before storing**
        const otp = generateOTP();
        const cleanedOTP = otp.toString().trim();

        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP for password change
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                email: user.email,
                otp_code: cleanedOTP, // **FIX 1B: Use the cleaned version here**
                otp_type: 'password_change',
                is_used: false,
                expires_at: expiresAt.toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        // Send OTP email
        await sendOTPEmail(user.email, otp, 'password_change');

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email for password change verification'
        });

    } catch (error) {
        console.error('Send password change OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while sending OTP'
        });
    }
}

// User Story 8: Delete Account with OTP Verification
async function deleteAccount(req, res) {
    try {
        const userId = req.user.userId;
        const { otp } = req.body;

        if (!otp) {
            return res.status(400).json({
                success: false,
                message: 'OTP is required for account deletion'
            });
        }

        // Get user email first
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Clean the OTP (remove spaces)
        const cleanOTP = otp.toString().trim();

        // Verify OTP for account deletion
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', user.email)
            .eq('otp_code', cleanOTP) // **Using cleanOTP for query**
            .eq('otp_type', 'account_deletion')
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        if (new Date(otpData.expires_at) < new Date()) { // Simplified expiry check
            return res.status(400).json({
                success: false,
                message: 'OTP has expired'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // Delete user's OTPs first
        await supabase
            .from('otps')
            .delete()
            .eq('email', user.email);

        // Delete user account
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('user_id', userId);

        if (deleteError) {
            throw deleteError;
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
    }
}

// New function: Send OTP for account deletion
async function sendAccountDeletionOTP(req, res) {
    try {
        const userId = req.user.userId;

        // Get user email
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('email')
            .eq('user_id', userId)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // **FIX 1A (Applied to sendAccountDeletionOTP): Get OTP and clean it before storing**
        const otp = generateOTP();
        const cleanedOTP = otp.toString().trim();

        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // Insert OTP for account deletion
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                email: user.email,
                otp_code: cleanedOTP, // **FIX 1B: Use the cleaned version here**
                otp_type: 'account_deletion',
                is_used: false,
                expires_at: expiresAt.toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        // Send OTP email
        await sendOTPEmail(user.email, otp, 'account_deletion');

        res.status(200).json({
            success: true,
            message: 'OTP sent to your email for account deletion verification'
        });

    } catch (error) {
        console.error('Send account deletion OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while sending OTP'
        });
    }
}

// ========== NEW FUNCTIONS FOR EMAIL VERIFICATION FEATURE ==========

// Function 1: Check email verification status
// ========== NEW FUNCTIONS FOR EMAIL VERIFICATION FEATURE ==========

// Function 1: Check email verification status
// Function 1: Check email verification status
async function checkEmailVerification(req, res) {
    try {
        const { email, password } = req.body;

        console.log('📧 Checking account verification for:', email);

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // 1. Get user from database
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (userError || !user) {
            console.log('❌ Account not found');
            return res.status(404).json({
                success: false,
                message: 'Account not found. Please sign up first.'
            });
        }

        // 2. Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            console.log('❌ Invalid password');
            return res.status(401).json({
                success: false,
                message: 'Invalid password. Please try again.'
            });
        }

        // 3. Check if account is already verified
        if (user.is_verified) {
            console.log('✅ Account already verified');
            return res.status(200).json({
                success: true,
                verified: true,
                message: 'Your account is already verified.'
            });
        }

        // 4. Account exists but not verified
        console.log('📨 Account exists but not verified');
        return res.status(200).json({
            success: true,
            verified: false,
            message: 'Account found but not verified. An OTP has been sent to your email.',
            userId: user.user_id,
            email: user.email
        });

    } catch (error) {
        console.error('❌ Check account verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
}

// Function 2: Resend verification OTP (for existing unverified users)
async function resendVerificationOTP(req, res) {
    try {
        const { email } = req.body;

        console.log('🔄 Resending verification OTP to:', email);

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        // 1. Find user by email
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id, is_verified')
            .eq('email', email)
            .single();

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found.'
            });
        }

        // 2. Check if user is already verified
        if (user.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified.'
            });
        }

        // 3. Generate new OTP
        const otp = generateOTP();
        const cleanedOTP = otp.toString().trim();
        const otpId = generateUUID();
        const expiresAt = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000);

        // 4. Insert OTP - use 'verify_account' type for existing users
        const { error: otpInsertError } = await supabase
            .from('otps')
            .insert({
                otp_id: otpId,
                email: email,
                otp_code: cleanedOTP,
                otp_type: 'verify_account',  // NEW: Changed from 'signup' to 'verify_account'
                is_used: false,
                expires_at: expiresAt.toISOString(),
                created_at: new Date().toISOString()
            });

        if (otpInsertError) {
            console.error('OTP insert error:', otpInsertError);
            throw otpInsertError;
        }

        // 5. Send OTP via email
        await sendOTPEmail(email, otp, 'verify_account');  // NEW: Use 'verify_account' type

        console.log('✅ Verification OTP resent successfully');

        res.status(200).json({
            success: true,
            message: 'New verification OTP sent successfully to your email.',
            email: email
        });

    } catch (error) {
        console.error('❌ Resend OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send OTP. Please try again.'
        });
    }
}

// Function 3: Verify email OTP (for existing users)
async function verifyEmailOTP(req, res) {
    try {
        const { email, otp } = req.body;

        console.log('🔑 Verifying email OTP for existing user:', email);

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Clean the OTP
        const cleanOTP = otp.toString().trim();

        // 1. Find OTP record - SPECIFICALLY for 'verify_account' type
        const { data: otpRecords, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', cleanOTP)
            .eq('otp_type', 'verify_account')  // NEW: Only accept 'verify_account' type
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1);

        console.log('📊 OTP Query Results:', { 
            recordsCount: otpRecords ? otpRecords.length : 0,
            error: otpError 
        });

        if (otpError) {
            console.error('❌ OTP Query Error:', otpError);
        }

        const otpData = otpRecords && otpRecords.length > 0 ? otpRecords[0] : null;

        if (!otpData) {
            console.log('❌ No valid OTP found for account verification');
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP or OTP type mismatch'
            });
        }

        // 2. Check OTP expiry
        if (new Date(otpData.expires_at) < new Date()) {
            console.log('❌ OTP Expired');
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        console.log('✅ OTP Valid - Proceeding with account verification');

        // 3. Mark OTP as used
        await supabase
            .from('otps')
            .update({ is_used: true })
            .eq('otp_id', otpData.otp_id);

        // 4. Verify user (update is_verified to true)
        await supabase
            .from('users')
            .update({ 
                is_verified: true,
                updated_at: new Date().toISOString()
            })
            .eq('email', email);

        console.log('🎉 Account verified successfully');

        res.status(200).json({
            success: true,
            message: 'Account verified successfully! You can now login to your account.',
            email: email
        });

    } catch (error) {
        console.error('❌ Verify email OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify account. Please try again.'
        });
    }
}

// Function to verify reset OTP (without resetting password)
async function verifyResetOTP(req, res) {
    try {
        const { email, otp } = req.body;

        console.log('🔑 Verifying reset OTP for:', email);

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Clean the OTP
        const cleanOTP = otp.toString().trim();

        // Find OTP - SPECIFICALLY for 'reset' type
        const { data: otpData, error: otpError } = await supabase
            .from('otps')
            .select('*')
            .eq('email', email)
            .eq('otp_code', cleanOTP)
            .eq('otp_type', 'reset')  // Only accept 'reset' type
            .eq('is_used', false)
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (otpError || !otpData) {
            console.log('❌ No valid reset OTP found');
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Check OTP expiry
        if (new Date(otpData.expires_at) < new Date()) {
            console.log('❌ Reset OTP Expired');
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        console.log('✅ Reset OTP is valid');

        // Note: We DON'T mark OTP as used here because it will be used in resetPassword
        // We only mark as used when password is actually reset

        res.status(200).json({
            success: true,
            message: 'OTP verified successfully',
            email: email
        });

    } catch (error) {
        console.error('❌ Verify reset OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify OTP. Please try again.'
        });
    }
}

// At the end of authController.js, make sure you have:
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
    deleteAccount,
    sendPasswordChangeOTP,  
    sendAccountDeletionOTP,
    // New functions for email verification
    checkEmailVerification,
    resendVerificationOTP,
    verifyEmailOTP,
    // New function for OTP verification only
    verifyResetOTP
};