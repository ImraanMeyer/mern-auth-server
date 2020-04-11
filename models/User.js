const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const crypto = require('crypto');

// User Schema
const userSchema = new Schema({
    name: {
        type: String,
        trim: true,
        required: true,
        max: 32
    },
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true,
        lowercase: true
    },
    hashed_password: {
        type: String,
        required: true,
    },
    salt: String,
    role: {
        type: String,
        default: 'subscriber'
    },
    resetPasswordLink: {
        data: String,
        default: ''
    }
}, { timestamps: true });

// Virtual Fill
userSchema
    .virtual('password')
    .set(function(password) {
        this._password = password;
        this.salt = this.generateSalt();
        this.hashed_password = this.encryptPassword(password);
    })
    .get(function() {
        return this._password
    })

// Methods
userSchema.methods = {
    authenticate: function(plainText) {
        return this.encryptPassword(plainText) === this.hashed_password; // true || false
    },

    encryptPassword: function(password) {
        if (!password) return ''
        try {
            return crypto
                .createHmac('sha1', this.salt)
                .update(password)
                .digest('hex');
        } catch (err) {
            return ''
        }
    },

    generateSalt: function() {
        return Math.round(new Date().valueOf() * Math.random() + '')
    }
}

module.exports = mongoose.model('User', userSchema);