const router = require('express').Router();
const rateLimit = require('express-rate-limit');
const Log = require("../Database/log");

const {
    memberSignup,
    memberLogin,
    memberAuth,
    checkRole,
    initiatePasswordRecovery,
    resetPassword

} = require("../Controller/authFunctions");

const generate2FA = async (req, res) => {
    const { email } = req.body;
    const member = await Member.findOne({ email });
    if (!member) {
        return res.status(404).json({ message: "Member not found" });
    }

    // Generate a secret
    const secret = speakeasy.generateSecret({ length: 20 });
    member.twoFASecret = secret.base32;
    member.is2FAEnabled = true;
    await member.save();

    // Generate a QR code
    const otpauth_url = speakeasy.otpauthURL({
        secret: secret.base32,
        label: encodeURIComponent(`MyAppName (${email})`),
        issuer: 'MyAppName',
        encoding: 'base32'
    });

    QRCode.toDataURL(otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ message: "Error generating QR code" });
        res.json({ qrCode: data_url });
    });
};

// In userRouter.js
router.get("/logs", memberAuth, checkRole(["executive"]), async (req, res) => {
    try {
        const { status } = req.query; // Get the status from query parameters
        let query = {};
        if (status) {
            query.status = status;
        }

        const logs = await Log.find(query).sort({ timestamp: -1 });
        if (!logs) {
            return res.status(404).json({ message: "No logs found" });
        }
        res.status(200).json(logs);
    } catch (err) {
        console.error("Error fetching logs:", err); // Log the error for debugging
        res.status(500).json({ message: "Internal server error while fetching logs" });
    }
});

router.get("/executives", memberAuth, checkRole(["executive"]), async (req, res) => {
    try {
        const executives = await Member.find({ role: 'executive' }, 'email');
        if (!executives || executives.length === 0) {
            return res.status(404).json({ message: "No executives found" });
        }
        res.status(200).json(executives.map(exec => exec.email));
    } catch (err) {
        console.error("Error fetching executives:", err); // Log the error for debugging
        res.status(500).json({ message: "Internal server error while fetching executives" });
    }
});

// Route to genertae 2fa
router.post("/generate-2fa", memberAuth, generate2FA);

// Routes for password recovery
router.post("/forgot-password", initiatePasswordRecovery);
router.post("/reset-password", resetPassword);

// Executive Registration Route
router.post("/register-executive", async (req, res) => {
    await memberSignup(req.body, 'executive', res);
});

// Management Registration Route
router.post("/register-management", async (req, res) => {
    await memberSignup(req.body, 'management', res);
});

// Management Registration Route
router.post("/register-technical", async (req, res) => {
    await memberSignup(req.body, 'technical', res);
});

// Customer Registration Route
router.post("/register-customer", async (req, res) => {
    await memberSignup(req.body, 'customer', res);
});

// Login routes for different roles with rate limiting
// Executive Login Route
router.post("/login-executive", async (req, res) => {
    await memberLogin(req.body, "executive", res);
});

// Management Login Route 
router.post("/login-management", async (req, res) => {
    await memberLogin(req.body, "management", res);
});

// Technical Login Route
router.post("/login-technical", async (req, res) => {
    await memberLogin(req.body, "technical", res);
});

// Customer Login Route
router.post("/login-customer", async (req, res) => {
    await memberLogin(req.body, "customer", res);
});


// Logout Route ---------------------------------------------------------------------------------------------
router.post("/logout", async (req, res) => {
    await logout(req, res);
});

// Protected routes for different roles
// Executive protected role
router.get(
    "/executive-protected",
    memberAuth,
    checkRole(["executive"]),
    async (req, res) => {
        return res.json(`Welcome ${req.name}`);
    }
);

// Management protected role
router.get(
    "/management-protected",
    memberAuth,
    checkRole(["management"]),
    async (req, res) => {
        return res.json(`Welcome ${req.name}`);
    }
);

// Technical protected role
router.get(
    "/technical-protected",
    memberAuth,
    checkRole(["technical"]),
    async (req, res) => {
        return res.json(`Welcome ${req.name}`);
    }
);

// Customer protected role
router.get(
    "/customer-protected",
    memberAuth,
    checkRole(["customer"]),
    async (req, res) => {
        return res.json(`Welcome ${req.name}`);
    }
);

// public unprotected route
router.get(
    "/public", (req, res) => {
        return res.status(200).json("Public Domain")    })
        
module.exports = router;