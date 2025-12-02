const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

async function sendOTPEmail(email, otp, type) {
    let subject, message;
    
    switch(type) {
        case 'signup':
            subject = 'Verify Your New BookNest Account';
            message = `Your OTP for new account verification is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
            break;
            
        case 'verify_account':  // NEW: For existing users verifying their account
            subject = 'Verify Your BookNest Account';
            message = `Your OTP for account verification is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
            break;
            
        case 'reset':
            subject = 'Reset Your BookNest Password';
            message = `Your OTP for password reset is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
            break;
            
        case 'password_change':
            subject = 'Change Your BookNest Password';
            message = `Your OTP for password change is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
            break;
            
        case 'account_deletion':
            subject = 'Confirm BookNest Account Deletion';
            message = `Your OTP for account deletion is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
            break;
            
        default:
            subject = 'Your BookNest OTP Code';
            message = `Your OTP is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.`;
    }

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: subject,
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 10px;">
                <div style="text-align: center; background-color: #a96b47; padding: 20px; border-radius: 10px 10px 0 0;">
                    <h1 style="color: white; margin: 0;">BookNest</h1>
                </div>
                <div style="padding: 30px;">
                    <h2 style="color: #333;">${subject}</h2>
                    <p style="font-size: 16px; line-height: 1.6;">Hello,</p>
                    <p style="font-size: 16px; line-height: 1.6;">${message}</p>
                    <div style="background-color: #f4f4f4; padding: 25px; margin: 30px 0; text-align: center; border-radius: 8px; border: 2px dashed #a96b47;">
                        <h1 style="color: #a96b47; margin: 0; letter-spacing: 8px; font-size: 36px;">${otp}</h1>
                    </div>
                    <p style="font-size: 14px; color: #666;">This OTP is valid for ${process.env.OTP_EXPIRY_MINUTES || 10} minutes.</p>
                    <p style="font-size: 14px; color: #666;">If you didn't request this, please ignore this email.</p>
                </div>
                <div style="background-color: #f9f9f9; padding: 15px; text-align: center; border-radius: 0 0 10px 10px; border-top: 1px solid #e0e0e0;">
                    <p style="font-size: 12px; color: #888; margin: 0;">
                        This is an automated message from BookNest. Please do not reply to this email.
                    </p>
                </div>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`OTP email (${type}) sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Failed to send OTP email');
    }
}

module.exports = { sendOTPEmail };