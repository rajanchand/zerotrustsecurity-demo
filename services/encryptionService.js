var crypto = require('crypto');

var ALGORITHM = 'aes-256-gcm';
var IV_LENGTH = 16;

// get 32 byte key from env variable
function getKey() {
    var secret = process.env.ENCRYPTION_KEY || process.env.SESSION_SECRET || 'zts-default-key';
    return crypto.createHash('sha256').update(secret).digest();
}

// encrypt a string, returns "iv:authTag:ciphertext" format
function encrypt(text) {
    if (!text) return text;

    var key = getKey();
    var iv = crypto.randomBytes(IV_LENGTH);
    var cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    var encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    var tag = cipher.getAuthTag();

    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted;
}

// decrypt a string from "iv:authTag:ciphertext" format
function decrypt(encrypted) {
    if (!encrypted) return encrypted;

    var parts = encrypted.split(':');
    if (parts.length !== 3) {
        // not encrypted, return as is
        return encrypted;
    }

    var key = getKey();
    var iv = Buffer.from(parts[0], 'hex');
    var tag = Buffer.from(parts[1], 'hex');
    var ciphertext = parts[2];

    var decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    var decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};
