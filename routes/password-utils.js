const crypto = require('crypto');
const AppDB = require('../db');

class InvalidCredentialsError extends Error {}

module.exports = {
    InvalidCredentialsError,

    calculatePasswordHash: async function (password, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
                if (err) {
                    reject(err);
                } else {
                    resolve(hashedPassword)
                }
            });
        });
    },

    authenticateUser: async function(userId, password) {
        return new Promise(async (resolve, reject) => {
            const db = new AppDB();
            try {
                const user = await db.findUserByEmail(userId?.toLowerCase());
                if (!user) {
                    reject(new InvalidCredentialsError())
                } else {
                    const passwordHash = await this.calculatePasswordHash(password, user.salt);
                    if (!crypto.timingSafeEqual(user.password_hash, passwordHash)) {
                        reject(new InvalidCredentialsError());
                    } else {
                        resolve(user);
                    }
                }
            } finally {
                await db.close();
            }
        });
    }
}
