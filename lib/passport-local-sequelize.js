var util = require('util');
var crypto = require('crypto');
var _ = require('lodash');
var Sequelize = require('sequelize');
var LocalStrategy = require('passport-local').Strategy;

// The default option values
var defaultAttachOptions = {
    activationkeylen:  8,
    resetPasswordkeylen:  8,
    saltlen:  32,
    iterations:  12000,
    keylen:  512,
    digest: 'sha512',
    usernameField: 'username',
    usernameLowerCase: false,
    activationRequired: false,
    hashField: 'hash',
    saltField: 'salt',
    activationKeyField: 'activationKey',
    resetPasswordKeyField: 'resetPasswordKey',
    saveLoginAttemps: false,
    lastLoginField: 'lastLogin',
    loginsField: 'logins',
    incorrectPasswordError: 'Incorrect password',
    incorrectUsernameError: 'Incorrect username',
    invalidActivationKeyError: 'Invalid activation key',
    invalidResetPasswordKeyError: 'Invalid reset password key',
    missingUsernameError: 'Field %s is not set',
    missingFieldError: 'Field %s is not set',
    missingPasswordError: 'Password argument not set!',
    userExistsError: 'User already exists with %s',
    activationError: 'Email activation required'
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
        type: Sequelize.STRING,
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
    }
};

var shimPbkdf2 = function (password, salt, iterations, keylen, digest, callback) {
    var params = [password, salt, iterations, keylen, callback];
    var nodeVersion = Number(process.version.match(/^v(\d+\.\d+)/)[1]);
    if (nodeVersion >= 0.12) {
        params.splice(4, 0, digest);
    }
    crypto.pbkdf2.apply(this, params);
};

var attachToUser = function (UserSchema, options) {
    // Get our options with default values for things not passed in
    options = _.defaults(options || {}, defaultAttachOptions);

    UserSchema.options.hooks.beforeCreate = function (user, next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            user[options.usernameField] = user[options.usernameField].toLowerCase();
        }
        if (typeof(next) === 'function') {
            next();
        }
    };

    UserSchema.DAO.prototype.setPassword = function (password, cb) {
        if (!password) {
            return cb(new Error(options.missingPasswordError));
        }

        var self = this;

        crypto.randomBytes(options.saltlen, function (err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString('hex');
            shimPbkdf2(password, salt, options.iterations, options.keylen, options.digest, function (err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self.set(options.hashField, new Buffer(hashRaw, 'binary').toString('hex'));
                self.set(options.saltField, salt);

                cb(null, self);
            });
        });
    };

    UserSchema.DAO.prototype.setActivationKey = function (cb) {
        var self = this;

        if (options.activationRequired) {
            crypto.randomBytes(options.activationkeylen, function (err, buf) {
                if (err) {
                    return cb(err);
                }

                var randomHex = buf.toString('hex');
                self.set(options.activationKeyField, randomHex);
                cb(null, self);

            });
        } else {
            cb(null, self);
        }
    };

    UserSchema.DAO.prototype.authenticate = function (password, cb) {
        var self = this;
        // TODO: Fix callback and behavior to match passport
        shimPbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, options.digest, function (err, hashRaw) {
            if (err) {
                return cb(err);
            }

            var hash = new Buffer(hashRaw, 'binary').toString('hex');

            if (hash === self.get(options.hashField)) {
                if (options.saveLoginAttemps) {
                    self.set(options.lastLoginField, Date.now());
                    self.set(options.loginsField, self.get(options.loginsField) + 1);
                    self.save();
                }
                return cb(null, self);
            } else {
                return cb(null, false, { message: options.incorrectPasswordError });
            }
        });
    };

    UserSchema.authenticate = function () {
        var self = this;
        return function (username, password, cb) {
            self.findByUsername(username, function (err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: options.incorrectUsernameError });
                }
            });
        };
    };

    UserSchema.serializeUser = function () {
        return function (user, cb) {
            cb(null, user.get(options.usernameField));
        };
    };

    UserSchema.deserializeUser = function () {
        var self = this;
        return function (username, cb) {
            self.findByUsername(username, cb);
        };
    };

    UserSchema.register = function (user, password, cb) {
        var self = this;
        var fields = {};

        if (_.isString(user)) {
            // Create an instance of this in case user is passed as username
            fields[options.usernameField] = user;
            user = fields;
        }

        if (_.isObject(user)) {
            // Create an instance if user is passed as fields
            user = self.build(user);
        }

        if (user instanceof UserSchema.DAO) {
            if (!user.get(options.usernameField)) {
                return cb(new Error(util.format(options.missingUsernameError, options.usernameField)));
            }

            self.findByUsername(user.get(options.usernameField), function (err, existingUser) {
                if (err) { return cb(err); }

                if (existingUser) {
                    return cb(new Error(util.format(options.userExistsError, user.get(options.usernameField))));
                }
                user.setPassword(password, function (err, user) {
                    if (err) {
                        return cb(err);
                    }

                    user.setActivationKey(function (err, user) {

                        if (err) {
                            return cb(err);
                        }

                        user.save().complete(function (err) {
                            if (err) { return cb(err); }
                            cb(null, user);
                        });

                    });

                });
            });
        }
    };

    UserSchema.activate = function (email, password, activationKey, cb) {
        var self = this;
        var auth = self.authenticate();
        auth(email, password, function (err, user, info) {

            if (err) { return cb(err); }

            if (!user) { return cb(info); }

            if (user.get(options.activationKeyField) === activationKey) {
                user.updateAttributes({ verified: true, activationKey: 'null' }).complete(function (err) {
                    if (err) {
                        return cb(err);
                    }

                    return cb(null, user);
                });
            } else {
                return cb({ message: options.invalidActivationKeyError });
            }
        });
    };

    UserSchema.findByUsername = function (username, cb) {
        var queryParameters = {};

        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            username = username.toLowerCase();
        }

        queryParameters[options.usernameField] = username;

        var query = this.find({ where: queryParameters });
        if (options.selectFields) {
            query.select(options.selectFields);
        }
        query.then(function (user) {
            cb(null, user);
        });
        query.catch(function (err) {
            cb(err);
        });
    };

    UserSchema.setResetPasswordKey = function (username, cb) {
        var self = this;
        self.findByUsername(username, function (err, user) {
            if (err) { return cb(err); }
            if (!user) { return cb({ message: options.incorrectUsernameError }); }

            crypto.randomBytes(options.resetPasswordkeylen, function (err, buf) {
                if (err) { return cb(err); }
                var randomHex = buf.toString('hex');
                user.set(options.resetPasswordKeyField, randomHex);
                user.save().complete(function (err) {
                    if (err) { return cb(err); }
                    cb(null, user);
                });
            });
        });
    };

    UserSchema.resetPassword = function (username, password, resetPasswordKey, cb) {
        var self = this;
        self.findByUsername(username, function (err, user) {
            if (err) { return cb(err); }
            if (user.get(options.resetPasswordKeyField) === resetPasswordKey) {
                user.setPassword(password, function (err, user) {
                    if (err) { return cb(err); }
                    user.save().complete(function (err) {
                        if (err) { return cb(err); }
                        cb(null, user);
                    });
                });
            } else {
                return cb({ message: options.invalidResetPasswordKeyError });
            }
        });
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
