const { Schema, model } = require('mongoose');

const LogSchema = new Schema({
    action: { type: String, required: true }, // login
    role: { type: String, required: true }, // e.g., executive, customer
    email: { type: String, required: true }, // User's email
    timestamp: { type: Date, default: Date.now, index: { expires: 180 } }, // TTL index to auto-delete logs after 3 min for testing purposes but should be set to 1 month or more in reality
    status: { type: String, required: true }, // e.g., success, failure
    details: { type: String } // Additional details if any
});

module.exports = model('Log', LogSchema);
