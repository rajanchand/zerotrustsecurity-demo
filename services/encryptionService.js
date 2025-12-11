// services/encryptionService.js

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// derive a 32-byte key from the env secret
function getKey() {
    var secret = process.env.ENCRYPTION_KEY || process.env.SESSION_SECRET || 'zts-default-encryption-key';
    return crypto.createHash('sha256').update(secret).digest();
}

function encrypt(text) {
    if (!text) return text;

    var key = getKey();
    var iv = crypto.randomBytes(IV_LENGTH);
    var cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    var encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    var authTag = cipher.getAuthTag();

    // format: iv:authTag:ciphertext
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(cipherText) {
    if (!cipherText) return cipherText;

    // check if it looks encrypted (has the iv:tag:data format)
    var parts = cipherText.split(':');
    if (parts.length !== 3) {
        // not encrypted, return as-is (backwards compatibility)
        return cipherText;
    }

    var key = getKey();
    var iv = Buffer.from(parts[0], 'hex');
    var authTag = Buffer.from(parts[1], 'hex');
    var encrypted = parts[2];

    var decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

module.exports = { encrypt, decrypt };
