'use strict';

const unleash = require('unleash-server');
const auth = require('basic-auth');
const compare = require('tsscmp');
const cors = require('cors');

function check(credentials) {
    let valid = true;
    valid = compare(credentials.name, process.env.BASIC_AUTH_USERNAME) && valid;
    valid = compare(credentials.pass, process.env.BASIC_AUTH_PASSWORD) && valid;
    return valid;
}

function basicAuth(req, res, next) {
    const credentials = auth(req);

    if (credentials && check(credentials)) {
        const user = new unleash.User({email: 'production@medwing.com'});
        req.user = user;
        return next();
    }

    return res
        .status('401')
        .set({'WWW-Authenticate': 'Basic realm="unleash"'})
        .end('access denied');
}

function preHook(app) {
    app.use(cors());

    app.use((req, res, next) => {
        if (req.path.startsWith('/api/client') || req.path === '/health') {
            return next();
        }

        return basicAuth(req, res, next);
    });
}

const options = {
    enableLegacyRoutes: false,
    adminAuthentication: 'custom',
    preHook: preHook
}

unleash.start(options);
