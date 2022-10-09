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

var attachToUser = function (UserSchema, options) {
    // Get our options with default values for things not passed in
    options = _.defaults(options || {}, defaultAttachOptions);

    UserSchema.beforeCreate(function(user, op, next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            user[options.usernameField] = user[options.usernameField].toLowerCase();
        }
        if (typeof(next) === 'function') {
            next(null, user);
        }
    });

    UserSchema.prototype.setPassword = function (password, cb) {
        if (!password) {
            return cb(new Error(options.missingPasswordError));
        }

        var self = this;

        crypto.randomBytes(options.saltlen, function (err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString('hex');

            crypto.pbkdf2(password, salt, options.iterations, options.keylen, options.digest, function (err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self.set(options.hashField, Buffer.from(hashRaw).toString('hex'));
                self.set(options.saltField, salt);

                cb(null, self);
            });
        });
    };

    UserSchema.prototype.setActivationKey = function (cb) {

        var self = this;

        if (!options.activationRequired) {
            return cb(null, self);
        }

        crypto.randomBytes(options.activationkeylen, function (err, buf) {
            if (err) {
                return cb(err);
            }

            var randomHex = buf.toString('hex');
            self.set(options.activationKeyField, randomHex);
            cb(null, self);

        });
    };

    UserSchema.prototype.authenticate = function (password, cb) {
        var self = this;

        // prevent to throw error from crypto.pbkdf2
        if (!this.get(options.saltField)) {
            return cb(null, false, { message: options.noSaltValueStoredError });
        }

        crypto.pbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, options.digest, function (err, hashRaw) {
            if (err) {
                return cb(err);
            }

            var hash = Buffer.from(hashRaw).toString('hex');

            if (hash === self.get(options.hashField)) {
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
        var self = this,
            fields = {};

        if (user instanceof UserSchema) {
            // Do nothing
        } else if (_.isString(user)) {
            // Create an instance of this in case user is passed as username
            fields[options.usernameField] = user;

            user = self.build(fields);
        } else if (_.isObject(user)) {
            // Create an instance if user is passed as fields
            user = self.build(user);
        }

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

                    user.save()
                    .then(function() {
                        cb(null, user);
                    })
                    .catch(function (err) {
                        return cb(err);
                    });

                });

            });
        });
    };

    UserSchema.activate = function (username, password, activationKey, cb) {
        var self = this;
        var auth = self.authenticate();
        auth(username, password, function (err, user, info) {

            if (err) { return cb(err); }

            if (!user) { return cb(info); }

            if (user.get(options.activationKeyField) === activationKey) {
                user.update({ verified: true, activationKey: 'null' })
                .then(function() {
                  return cb(null, user);
                })
                .catch(function (err) {
                  return cb(err);
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

        var query = this.findOne({ where: queryParameters });
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
                user.save()
                .then(function() {
                  return cb(null, user);
                })
                .catch(function (err) {
                 return cb(err);
                });
            });
        });
    };

    UserSchema.resetPassword = function (username, password, resetPasswordKey, cb) {
        var self = this;
        self.findByUsername(username, function (err, user) {
            if (err) { return cb(err); }
            if (!user) { return cb({ message: options.incorrectUsernameError }); }
            if (user.get(options.resetPasswordKeyField) === resetPasswordKey) {
                user.setPassword(password, function (err, user) {
                    if (err) { return cb(err); }
                    user.set(options.resetPasswordKeyField, null);
                    user.save()
                    .then(function() {
                      cb(null, user);
                    })
                    .catch(function (err) {
                      return cb(err);
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
