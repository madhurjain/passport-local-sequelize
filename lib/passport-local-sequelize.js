var util = require('util'),
    crypto = require('crypto'),
    LocalStrategy = require('passport-local').Strategy,
    BadRequestError = require('passport-local').BadRequestError;

module.exports = function(schema, options) {
    options = options || {};
    options.activationkeylen = options.activationkeylen || 8;
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    
    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'username';
    
    // option to convert username to lowercase when finding
    options.usernameLowerCase = options.usernameLowerCase || false;
    
    // option to make activation mandatory
    options.activationRequired = options.activationRequired || false;
    
    options.hashField = options.hashField || 'hash';
    options.saltField = options.saltField || 'salt';
    options.activationKeyField = options.activationKeyField || 'activationKey';
    options.incorrectPasswordError = options.incorrectPasswordError || 'Incorrect password';
    options.incorrectUsernameError = options.incorrectUsernameError || 'Incorrect username';
    options.invalidActivationKeyError = options.invalidActivationKeyError || 'Invalid activation key';
    options.missingUsernameError = options.missingUsernameError || 'Field %s is not set';
    options.missingActivationKeyError = options.missingActivationKeyError || 'Field %s is not set';
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.userExistsError = options.userExistsError || 'User already exists with %s';
    options.activationError = options.activationError || 'Email activation required';
    
    /*
    var schemaFields = {};
    if (!schema.path(options.usernameField)) {
    	schemaFields[options.usernameField] = String;
    }
    schemaFields[options.hashField] = String;
    schemaFields[options.saltField] = String;

    schema.add(schemaFields);

    */
    
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
    
    schema.DAO.prototype.setActivationKey = function (cb) {  
    
        var self = this;
        
        if(!options.activationRequired) {
            return cb(null, self);
        }
               
        crypto.randomBytes(options.activationkeylen, function(err, buf) {
            if (err) {
                return cb(err);
            }
            
            var randomHex = buf.toString('hex');
            self.set(options.activationKeyField, randomHex);
            cb(null, self);
          
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
        // Create an instance of this in case user isn't already an instance        
        /*
        if (!(user instanceof schema)) {
            user = new schema(user);
        }
        */

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
                
                user.setActivationKey(function(err, user) {
                
                    if(err) {
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
        });
    };
    
    schema.activate = function(email, activationKey, cb) {           

        var self = this;
        self.findByUsername(email, function(err, existingUser) {
            if (err) { return cb(err); }
            
            if (existingUser) {                
                if(existingUser.get(options.activationKeyField) === activationKey)
                {
                    existingUser.updateAttributes({ verified: true }).complete(function(err) {
                        if (err) {
                            return cb(err);
                        }

                        return cb(null, existingUser);
                    });
                }
                else
                {
                    return cb({ message: options.invalidActivationKeyError });                   
                }
            } else {
                return cb({ message: options.incorrectUsernameError });
            }
        });
    }

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
