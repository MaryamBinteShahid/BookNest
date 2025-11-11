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
    const subject = type === 'signup' ? 'Verify Your Email' : 'Reset Your Password';
    const message = type === 'signup'
        ? `Your OTP for email verification is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.`
        : `Your OTP for password reset is: ${otp}. This code will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.`;

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: subject,
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>${subject}</h2>
                <p>${message}</p>
                <div style="background-color: #f4f4f4; padding: 15px; margin: 20px 0; text-align: center;">
                    <h1 style="color: #333; letter-spacing: 5px;">${otp}</h1>
                </div>
                <p style="color: #666;">If you didn't request this, please ignore this email.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`OTP email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Failed to send OTP email');
    }
}

module.exports = { sendOTPEmail };