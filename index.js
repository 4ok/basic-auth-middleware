'use strict';

var basicAuth = require('basic-auth');

var BasicAuthMiddleware = function (users, options) {

    if (!options) {
        options = {};
    }

    if (!users) {
        throw new Error('Param "users" required');
    }

    this.get = function (action) {

        if (!action) {
            throw new Error('Param "action" required');
        }

        var result;

        switch (action) {
            case 'check' : {
                result = _check;
                break;
            }
            case 'login' : {
                result = _login;
                break;
            }
            case 'logout' : {
                result = _logout;
                break;
            }
        }

        return result;
    };

    var _login = function (request, response, next) {
        var isNotAuth = true;

        if (request.session.notShowBasicAuth) {
            var currentUser = basicAuth(request);

            if (currentUser) {
                isNotAuth = users.every(function (user) {
                    var result = true;

                    if (currentUser.name === user.name
                        && currentUser.pass === user.pass
                    ) {
                        request.session.isAuth = true;
                        request.session.notShowBasicAuth = false;

                        response.redirect(options.urls.root);

                        result = false;
                    }

                    return result;
                });
            }
        }

        if (isNotAuth) {
            response.setHeader('WWW-Authenticate', 'Basic realm=Authorization Required');
            request.session.notShowBasicAuth = true;

            response.sendStatus(401);
        }
    };

    var _logout = function (request, response, next) {
        var charset = options.charset || 'utf-8';

        request.session.isAuth = false;

        if (options.headers) {

            for (var key in options.headers) {
                response.setHeader(key, options.headers[key]);
            }
        }

        var responseData = options.responseText || 'You are logged out';

        response.end(responseData);
    };

    var _check = function (request, response, next) {

        if (!request.session.isAuth) {
            response.redirect(options.urls.login);
        } else {
            next();
        }
    };
};

module.exports = function (users, options) {
    var result;

    if (!(this instanceof BasicAuthMiddleware)) {
        result = new BasicAuthMiddleware(users, options);
    }

    return result;
};