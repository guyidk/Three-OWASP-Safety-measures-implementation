// Import necessary modules
const bcrypt = require("bcrypt"); // Library for hashing passwords
const jwt = require("jsonwebtoken"); // Library for generating and verifying JWT tokens
require('dotenv').config(); // Load environment variables from a .env file
const Member = require("../Database/member"); // Mongoose model for Member schema
const axios = require('axios'); // Library for making HTTP requests
const speakeasy = require('speakeasy'); // Library for handling 2FA (Two-Factor Authentication)
const QRCode = require('qrcode'); // Library for generating QR codes
const nodemailer = require('nodemailer'); // Add this line to import nodemailer
const Log = require("../Database/log"); // Mongoose model for Log schema
const crypto = require('crypto'); // Library for generating random tokens

// Function to check for consecutive login failures and notify executives
const checkConsecutiveFailuresAndNotify = async (email, role) => {
    try {
        // Fetch the last three login attempts for this email and role
        const recentFailures = await Log.find({ action: 'login', role, email, status: 'failure' })
                                        .sort({ timestamp: -1 })
                                        .limit(3);

        // Check if there are three consecutive failures
        if (recentFailures.length === 3) {
            const timeStamps = recentFailures.map(log => log.timestamp);
            const allWithinShortTime = (timeStamps[0] - timeStamps[2]) < (15 * 60 * 1000); // 15 minutes

            if (allWithinShortTime) {
                // Fetch all executive emails
                const executives = await Member.find({ role: 'executive' }, 'email');
                const executiveEmails = executives.map(exec => exec.email);

                // Send notification email to all executives
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: executiveEmails,
                    subject: 'Suspicious Activity Detected',
                    text: `There have been three consecutive login failures for the email: ${email} with role: ${role}. Please investigate.`
                };

                await transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error("Error sending email:", error);
                    }
                });
            }
        }
    } catch (err) {
        console.error("Error in checkConsecutiveFailuresAndNotify:", err);
    }
};

// Function to verify a 2FA (Two-Factor Authentication) token
const verify2FA = (secret, token) => {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 1 // Allow a margin of error of 1 time step (usually 30 seconds)
    });
};

// Configure the email transporter for sending emails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Function to send a password reset email
const sendPasswordResetEmail = async (email, token) => {
    const resetURL = `http://localhost:5000/reset-password?token=${token}`;
    let mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset Request',
        text: `You requested a password reset. Please click on the following link to reset your password: ${resetURL}`
    };

    await transporter.sendMail(mailOptions);
};

// Function to handle password recovery initiation
const initiatePasswordRecovery = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: "Email is required." });
        }

        const member = await Member.findOne({ email });
        if (!member) {
            return res.status(404).json({ message: "Email not found." });
        }

        const token = crypto.randomBytes(20).toString('hex');
        member.resetPasswordToken = token;
        member.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now
        await member.save();

        await sendPasswordResetEmail(email, token);

        return res.status(200).json({ message: "Password reset link has been sent to your email." });
    } catch (err) {
        return res.status(500).json({ message: `${err.message}` });
    }
};

// Function to handle password reset
const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({ message: "New password is required." });
        }

        const member = await Member.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!member) {
            return res.status(400).json({ message: "Password reset token is invalid or has expired." });
        }

        member.password = await bcrypt.hash(newPassword, 12);
        member.resetPasswordToken = undefined;
        member.resetPasswordExpires = undefined;
        await member.save();

        return res.status(200).json({ message: "Password has been successfully reset." });
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};

// Function to verify reCAPTCHA token
const verifyRecaptcha = async (recaptchaToken) => {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`);
        return response.data.success;
    } catch (err) {
        console.error(err);
        return false;
    }
};

// Validate email format using a regular expression
const validateEmailFormat = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
};

// Validate if required fields are present and not empty
const validateFields = (fields) => {
    for (const field in fields) {
        if (!fields[field]) {
            return `${field} is required.`;
        }
    }
    return null;
};

// Function to handle member signup
const memberSignup = async (req, role, res) => {
    try {
        const { name, email, password, recaptchaToken } = req;

        const isHuman = await verifyRecaptcha(recaptchaToken);
        if (!isHuman) {
            return res.status(400).json({ message: "reCAPTCHA verification failed." });
        }

        // Validate required fields
        const emptyFieldError = validateFields({ name, email, password });
        if (emptyFieldError) {
            return res.status(400).json({ message: emptyFieldError });
        }

        // Validate email format
        if (!validateEmailFormat(email)) {
            return res.status(400).json({ message: "Invalid email format." });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ message: "Password too short. It needs to be at least 6 characters." });
        }

        // Check if the member name is already taken
        let nameNotTaken = await validateMemberName(name);
        if (!nameNotTaken) {
            await Log.create({ action: 'register', role, email, status: 'failure', details: 'register with a used member' });
            return res.status(400).json({ message: "Member is already registered." });
        }

        // Check if the email is already registered
        let emailNotRegistered = await validateEmail(email);
        if (!emailNotRegistered) {
            await Log.create({ action: 'register', role, email, status: 'failure', details: 'register with a used email' });
            return res.status(400).json({ message: "Email is already registered." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate 2FA secret
        const secret = speakeasy.generateSecret({ length: 20 });

        // Create a new member instance
        const newMember = new Member({
            name,
            email,
            password: hashedPassword,
            role,
            twoFASecret: secret.base32, // Store the 2FA secret
            is2FAEnabled: true // Initially set to false, to be enabled after setup
        });

        // Save the new member to the database
        await newMember.save();

        // Generate QR code URL
        const otpauth_url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: encodeURIComponent(`MyAppName (${email})`),
            issuer: 'MyAppName',
            encoding: 'base32'
        });

        // Generate the QR code
        QRCode.toDataURL(otpauth_url, (err, data_url) => {
            if (err) {
                console.error("Error generating QR code:", err);
                return res.status(500).json({ message: "Error generating QR code" });
            }

            // Send the QR code back to the frontend
            res.status(201).json({
                message: "Registration successful! Please scan the QR code to set up 2FA.",
                qrCode: data_url
            });
        });

    } catch (err) {
        // Handle server errors
        return res.status(500).json({ message: err.message });
    }
};


// Function to check if a member name is already taken
const validateMemberName = async (name) => {
    let member = await Member.findOne({ name });
    return member ? false : true;
};

// Function to check if an email is already registered
const validateEmail = async (email) => {
    let member = await Member.findOne({ email });
    return member ? false : true;
};

// Function to handle member login
const memberLogin = async (req, role, res) => {
    try {
        const { name, password, recaptchaToken, twoFAToken } = req;

        // Validate required fields
        const emptyFieldError = validateFields({ name, password });
        if (emptyFieldError) {
            return res.status(400).json({ message: emptyFieldError });
        }

        // Find member by name
        const member = await Member.findOne({ name });
        if (!member) {
            return res.status(404).json({ message: "Member name not found. Invalid login credentials." });
        }

        // Extract email from member after ensuring the member exists
        const email = member.email;

        // Check if the member's role matches the login role
        if (member.role !== role) {
            await Log.create({ action: 'login', role, email, status: 'failure', details: 'Loging from wrong role' });
            await checkConsecutiveFailuresAndNotify(email, role); // Check for consecutive failures
            return res.status(403).json({ message: "Please make sure you are logging in from the right role." });
        }


        // Compare the provided password with the stored hashed password
        let isMatch = await bcrypt.compare(password, member.password);
        if (!isMatch) {
            await Log.create({ action: 'login', role, email, status: 'failure', details: 'Invalid credentials' });
            await checkConsecutiveFailuresAndNotify(email, role); // Check for consecutive failures
            return res.status(403).json({ message: "Incorrect password or username" });
        }

        // Check if 2FA is enabled and verify the token
        if (member.is2FAEnabled) {
            if (!twoFAToken) {
                await Log.create({ action: 'login', role, email, status: 'failure', details: 'No given token' });
                await checkConsecutiveFailuresAndNotify(email, role); // Check for consecutive failures
                return res.status(403).json({ message: "2FA token required" });
            }

            const is2FAValid = verify2FA(member.twoFASecret, twoFAToken);
            if (!is2FAValid) {
                await Log.create({ action: 'login', role, email, status: 'failure', details: 'Invalid 2FA token' });
                await checkConsecutiveFailuresAndNotify(email, role); // Check for consecutive failures
                return res.status(403).json({ message: "Invalid 2FA token" });
            }
        }

        const isHuman = await verifyRecaptcha(recaptchaToken);
        if (!isHuman) {
            await Log.create({ action: 'login', role, email, status: 'failure', details: 'reCAPTCHA verification failed' });
            await checkConsecutiveFailuresAndNotify(email, role); // Check for consecutive failures
            return res.status(400).json({ message: "reCAPTCHA verification failed" });
        }

        // Generate a JWT token
        let jwtToken = jwt.sign(
            { role: member.role, name: member.name, email: member.email },
            process.env.APP_SECRET,
            { expiresIn: "1 days" }
        );
        // Log successful login
        await Log.create({ action: 'login', role, email, status: 'success', details: 'Successful login' });

        // Send success response with token
        return res.status(200).json({
            name: member.name,
            role: member.role,
            email: member.email,
            token: jwtToken,
            expiresIn: 168,
            message: "You have successfully logged in"
        });

    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
};


// Middleware for authenticating members using JWT
const memberAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(403).json({ message: "Missing Token" });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.APP_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Wrong Token" });
        }
        req.name = decoded.name;
        req.role = decoded.role;
        next();
    });
};

// Middleware for checking member roles
const checkRole = (roles) => async (req, res, next) => {
    let { name } = req;
    const member = await Member.findOne({ name });
    if (!roles.includes(member.role)) {
        await Log.create({ action: 'login', roles, email, status: 'failure', details: 'Login from wrong role' });
        return res.status(401).json("Sorry, you do not have access to this route.");
    }
    next();
};

// Export functions for use in other parts of the application
module.exports = {
    memberSignup,
    memberLogin,
    checkRole,
    memberAuth,
    initiatePasswordRecovery,
    resetPassword,
};