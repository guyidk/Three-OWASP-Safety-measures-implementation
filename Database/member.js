// Importing Schema and modal from mongoos module
const { Schema, model } = require('mongoose');

// Defining the schema for memeber
const MemberSchema = new Schema(
    {
        // Name field of the memeber
        name: {
            type: String, // Data type is string
            required: true // This feild is required
        },
        email: { type: String, required: true },
        role: {
            type: String, // Data type is boolean
            enum: ["executive", "management", "technical", "customer"] //The value of this field should be one of these
        },
        password: { type: String, required: true },
        twoFASecret: String,
        is2FAEnabled: { type: Boolean, default: true },
        resetPasswordToken: {
            type: String,
            default: null
        },
        resetPasswordExpires: {
            type: Date,
            default: null
        },resetPasswordToken: {
            type: String
        },
        resetPasswordExpires: {
            type: Date
        }
    },
    { timestamps: true }//Enable timestamps
);

// Exporting the Member Modal
module.exports = model('member', MemberSchema);