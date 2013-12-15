var util = require('util'),
    crypto = require('crypto'),
    LocalStrategy = require('passport-local').Strategy,
    BadRequestError = require('passport-local').BadRequestError;

module.exports = function(schema, options) {
    options = options || {};
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    
    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'username';
    
    // option to convert username to lowercase when finding
    options.usernameLowerCase = options.usernameLowerCase || false;
    
    options.hashField = options.hashField || 'hash';
    options.saltField = options.saltField || 'salt';
    options.incorrectPasswordError = options.incorrectPasswordError || 'Incorrect password';
    options.incorrectUsernameError = options.incorrectUsernameError || 'Incorrect username';
    options.missingUsernameError = options.missingUsernameError || 'Field %s is not set';
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.userExistsError = options.userExistsError || 'User already exists with name %s';    
    
    schema.options.hooks.beforeCreate = function(user, next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            user[options.usernameField] = user[options.usernameField].toLowerCase();
        }
        next();
    }
    
    schema.DAO.prototype.setPassword = function (password, cb) {
        if (!password) {
            return cb(new BadRequestError(options.missingPasswordError));
        }
        
        var self = this;

        crypto.randomBytes(options.saltlen, function(err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString('hex');

            crypto.pbkdf2(password, salt, options.iterations, options.keylen, function(err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self.set(options.hashField, new Buffer(hashRaw, 'binary').toString('hex'));
                self.set(options.saltField, salt);

                cb(null, self);
            });
        });
    };

    schema.DAO.prototype.authenticate = function(password, cb) {
        var self = this;
        // TODO: Fix callback and behavior to match passport
        crypto.pbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, function(err, hashRaw) {
            if (err) {
                return cb(err);
            }
            
            var hash = new Buffer(hashRaw, 'binary').toString('hex');

            if (hash === self.get(options.hashField)) {
                return cb(null, self);
            } else {
                return cb(null, false, { message: options.incorrectPasswordError });
            }
        });
    };

    schema.authenticate = function() {
        var self = this;
        return function(username, password, cb) {
            self.findByUsername(username, function(err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: options.incorrectUsernameError })
                }
            });
        }
    };

    schema.serializeUser = function() {
        return function(user, cb) {
            cb(null, user.get(options.usernameField));
        }
    };

    schema.deserializeUser = function() {
        var self = this;

        return function(username, cb) {
            self.findByUsername(username, cb);
        }
    };
    
    schema.register = function(user, password, cb) {
        if (!user.get(options.usernameField)) {
            return cb(new BadRequestError(util.format(options.missingUsernameError, options.usernameField)));
        }

        var self = this;
        self.findByUsername(user.get(options.usernameField), function(err, existingUser) {
            if (err) { return cb(err); }
            
            if (existingUser) {
                return cb(new BadRequestError(util.format(options.userExistsError, user.get(options.usernameField))));
            }
            
            user.setPassword(password, function(err, user) {
                if (err) {
                    return cb(err);
                }

                user.save().complete(function(err) {
                    if (err) {
                        return cb(err);
                    }

                    cb(null, user);
                });
            });
        });
    };

    schema.findByUsername = function(username, cb) {
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
        query.success(function(user){
            cb(null, user);
        });
        query.error(function(err){
            cb(err);
        });
    };

    schema.createStrategy = function() {
        return new LocalStrategy(options, this.authenticate());
    };
};
