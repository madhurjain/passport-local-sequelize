var util = require('util'),
    crypto = require('crypto'),
    _ = require('lodash'),
    Sequelize = require('sequelize'),
    LocalStrategy = require('passport-local').Strategy;

// The default option values
var defaultAttachOptions = {
    activationkeylen:  8,
    resetPasswordkeylen:  8,
    saltlen:  32,
    iterations:  12000,
    keylen:  512,
    digest:  'sha1',
    usernameField: 'username',
    usernameLowerCase: false,
    activationRequired: false,
    hashField: 'hash',
    saltField: 'salt',
    activationKeyField: 'activationKey',
    resetPasswordKeyField: 'resetPasswordKey',
    incorrectPasswordError: 'Incorrect password',
    incorrectUsernameError: 'Incorrect username',
    invalidActivationKeyError: 'Invalid activation key',
    invalidResetPasswordKeyError: 'Invalid reset password key',
    missingUsernameError: 'Field %s is not set',
    missingFieldError: 'Field %s is not set',
    missingPasswordError: 'Password argument not set!',
    userExistsError: 'User already exists with %s',
    activationError: 'Email activation required',
    noSaltValueStoredError: 'Authentication not possible. No salt value stored in db!'
};

// The default schema used when creating the User model
var defaultUserSchema = {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    username: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
    },
    hash: {
        type: Sequelize.TEXT,
        allowNull: false
    },
    salt: {
        type: Sequelize.STRING,
        allowNull: false
    },
    activationKey: {
        type: Sequelize.STRING,
        allowNull: true
    },
    resetPasswordKey: {
        type: Sequelize.STRING,
        allowNull: true
    },
    verified: {
        type: Sequelize.BOOLEAN,
        allowNull: true
    }
};

var pbkdf2Promisified = util.promisify(crypto.pbkdf2);
var randomBytes = util.promisify(crypto.randomBytes);

var attachToUser = function (UserSchema, options) {
    // Get our options with default values for things not passed in
    options = _.defaults(options || {}, defaultAttachOptions);

    UserSchema.beforeCreate(function(user) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            user[options.usernameField] = user[options.usernameField].toLowerCase();
        }
    });

    UserSchema.prototype.setPassword = function (password, cb) {
        const promise = Promise.resolve()
            .then(() => {
                if (!password) {
                    throw new Error(options.missingPasswordError);
                }
            })
            .then(() => randomBytes(options.saltlen))
            .then((saltBuffer) => saltBuffer.toString('hex'))
            .then((salt) => {
                this.set(options.saltField, salt);
                return salt;
            })
            .then((salt) => pbkdf2Promisified(password, salt, options.iterations, options.keylen, options.digest))
            .then((hashRaw) => {
              this.set(options.hashField, Buffer.from(hashRaw, 'binary').toString('hex'));
            })
            .then(() => this);
        
        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.prototype.setActivationKey = function (cb) {
        const promise = Promise.resolve()
            .then(() => {
                if (options.activationRequired) {
                    return randomBytes(options.activationkeylen)
                }
            })
            .then((buf) => {
                if (buf) {
                    this.set(options.activationKeyField, buf.toString('hex'));
                }
            })
            .then(() => this);

        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.prototype.authenticate = function (password, cb) {
        const promise = Promise.resolve()
            .then(() => {
                // prevent to throw error from crypto.pbkdf2
                if (!this.get(options.saltField)) {
                    return [{ message: options.noSaltValueStoredError }];
                } return [null, this.get(options.saltField)];
            })
            .then(([err, salt]) => {
                if (err) return [err];
                return Promise.all([null, pbkdf2Promisified(password, salt, options.iterations, options.keylen, options.digest)])
            })
            .then(([err, hash]) => {
                if (err) return [err, false];
                if (this.get(options.hashField) === Buffer.from(hash, 'binary').toString('hex')) {
                    return [null, this];
                } else return [{ message: options.incorrectPasswordError }, false];
            })

        if (!cb) {
            // Will lose error context if used as Promise
            return promise.then(([_, user]) => {
                return Promise.resolve(user);
            });
            }

        promise.then(([err, user]) => cb(null, user, err)).catch((err) => cb(err));
    };

    UserSchema.authenticate = function () {
        return (username, password, cb) => {
            if (cb) {
                this.findByUsername(username, (err, user) => {
                    if (err) { return cb(err); }
                    if (user) {
                        return user.authenticate(password, cb);
                    } else {
                        return cb(null, false, { message: options.incorrectUsernameError });
                    }
                });
            } else {
                // Different error handler needed compared to callback-style
                return Promise.resolve()
                    .then(() => this.findByUsername(username))
                    .then(user => {
                        if (user) {
                            return user.authenticate(password);
                        } else {
                            throw new Error({ message: options.incorrectUsernameError });
                        }
                    })
            }
        };
    };

    UserSchema.serializeUser = function () {
        return (user, cb) => {
            cb(null, user.get(options.usernameField));
        };
    };

    UserSchema.deserializeUser = function () {
        return (username, cb) => {
            this.findByUsername(username, cb);
        };
    };

    UserSchema.register = function (user, password, cb) {
        var fields = {};

        if (user instanceof UserSchema) {
            // Do nothing
        } else if (_.isString(user)) {
            // Create an instance of this in case user is passed as username
            fields[options.usernameField] = user;
            user = this.build(fields);
        } else if (_.isObject(user)) {
            // Create an instance if user is passed as fields
            user = this.build(user);
        }

        const promise = Promise.resolve()
            .then(() => {
                if (!user.get(options.usernameField)) {
                    throw new Error(util.format(options.missingUsernameError, options.usernameField));
                }
            })
            .then(() => this.findByUsername(user.get(options.usernameField)))
            .then((existingUser) => {
                if (existingUser) throw new Error(util.format(options.userExistsError, user.get(options.usernameField)));
                return user.setPassword(password);
            })
            .then(user => user.setActivationKey())
            .then(user => user.save())
            ;

        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.activate = function (username, password, activationKey, cb) {
        var auth = this.authenticate();

        const promise = auth(username, password)
            .then((user) => {
                if (!user) throw new Error(options.incorrectPasswordError);
                if (user.get(options.activationKeyField) !== activationKey) {
                    throw new Error(options.invalidActivationKeyError);
                }
                return user.update({ verified: true, activationKey: null })
            });

        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.findByUsername = function (username, cb) {
        var queryParameters = {};

        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            username = username.toLowerCase();
        }

        queryParameters[options.usernameField] = username;

        var query = this.findOne({ where: queryParameters });
        if (options.selectFields) {
            query.select(options.selectFields);
        }

        if (!cb) return query;

        query.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.setResetPasswordKey = function (username, cb) {
        const promise = Promise.resolve()
            .then(() => this.findByUsername(username))
            .then((user) => {
                if (!user) throw new Error(options.incorrectUsernameError);
                return Promise.all([user, randomBytes(options.resetPasswordkeylen)])
            })
            .then(([user, buf]) => {
                user.set(options.resetPasswordKeyField, buf.toString('hex'));
                return user.save();
            });

        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.resetPassword = function (username, password, resetPasswordKey, cb) {
        const promise = Promise.resolve()
            .then(() => this.findByUsername(username))
            .then((user) => {
                if (!user) throw new Error(options.incorrectUsernameError);
                if (user.get(options.resetPasswordKeyField) !== resetPasswordKey) {
                    throw new Error(options.invalidResetPasswordKeyError);
                };
                return user.setPassword(password)
            })
            .then((user) => {
                user.set(options.resetPasswordKeyField, null);
                return user.save();
            })

        if (!cb) {
            return promise;
        }
        
        promise.then((result) => cb(null, result)).catch((err) => cb(err));
    };

    UserSchema.createStrategy = function () {
        return new LocalStrategy(options, this.authenticate());
    };
};

var defineUser = function (sequelize, extraFields, attachOptions) {
    var schema = _.defaults(extraFields || {}, defaultUserSchema);

    var User = sequelize.define('User', schema);

    attachToUser(User, attachOptions);

    return User;
};

module.exports = {
    defaultAttachOptions: defaultAttachOptions,
    defaultUserSchema: defaultUserSchema,
    attachToUser: attachToUser,
    defineUser: defineUser
};
