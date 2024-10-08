/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
const FORM_ID = 'ap_cE5wuUyGqGMZrk82LNWx9r';
const interactive_login = new RegExp('^oidc-');
const database_sub = new RegExp('^auth0|');

async function checkForExistingAccount(event, api, email) {

    const {
        ManagementClient,
        AuthenticationClient
    } = require('auth0');

    const domain = event?.secrets?.domain || event.request?.hostname;

    let {
        value: token
    } = api.cache.get('management-token') || {};

    if (!token) {
        const {
            clientId,
            clientSecret
        } = event.secrets || {};

        const cc = new AuthenticationClient({
            domain,
            clientId,
            clientSecret
        });

        try {
            const {
                data
            } = await cc.oauth.clientCredentialsGrant({
                scope: `update:users read:users`,
                audience: `https://${domain}/api/v2/`
            });
            token = data?.access_token;

            if (!token) {
                console.log('failed get api v2 cc token');
                return;
            }
            console.log('cache MIS m2m token!');

            const result = api.cache.set('management-token', token, {
                ttl: data.expires_in * 1000
            });

            if (result?.type === 'error') {
                console.log('failed to set the token in the cache with error code', result.code);
            }
        } catch (err) {
            console.log('failed calling cc grant', err);
            return;
        }
    }

    const client = new ManagementClient({
        domain,
        token
    });

    try {
        return await client.usersByEmail.getByEmail({
            email: email
        });
    } catch (err) {
        console.log(err);
        return;
    }


}



async function exchangeAndVerify(api, domain, custom_domain, client_id, code_verifier, redirect_uri, code, nonce) {

    const axios = require('axios');

    console.log(`exchanging code: ${code}`);

    const {
        data: {
            id_token
        }
    } =
    await axios({
        method: 'post',
        url: `https://${custom_domain}/oauth/token`,
        data: {
            client_id,
            code,
            code_verifier,
            grant_type: 'authorization_code',
            redirect_uri
        },
        headers: {
            'Content-Type': 'application/json'
        },
        timeout: 5000 // 5 sec
    });

    console.log(`id_token: ${id_token}`);

    const jwt = require('jsonwebtoken');

    const jwksClient = require('jwks-rsa');

    const client = jwksClient({
        jwksUri: `https://${custom_domain}/.well-known/jwks.json`
    });

    function getKey(header, callback) {

        const {
            value: signingKey
        } = api.cache.get(`key-${header.kid}`) || {};

        if (!signingKey) {
            console.log(`cache MIS signing key: ${header.kid}`);

            client.getSigningKey(header.kid, (err, key) => {
                if (err) {
                    console.log('failed to download signing key: ', err.message);
                    return callback(err);
                }

                const signingKey = key.publicKey || key.rsaPublicKey;

                const result = api.cache.set(`key-${header.kid}`, signingKey);

                if (result?.type === 'error') {
                    console.log('failed to set signing key in the cache', result.code);
                }

                callback(null, signingKey);
            });
        } else {
            callback(null, signingKey);
        }
    }

    return new Promise((resolve, reject) => {
        jwt.verify(id_token, getKey, {
            issuer: `https://${custom_domain}/`,
            audience: client_id,
            nonce,
            algorithms: 'RS256'
        }, (err, decoded) => {
            if (err) reject(err);
            else resolve(decoded);
        });
    });
}

async function linkAndMakePrimary(event, api, token_sub, token_provider, makePrimary) {

    if (token_sub === event.user.user_id) {
        console.log("Skipping as already linked");
        return;
    }

    if (!makePrimary) {
        console.log(`linking ${token_sub} under ${event.user.user_id}`);
    } else {
        console.log(`linking ${event.user.user_id} under ${token_sub}`);
    }

    const {
        ManagementClient,
        AuthenticationClient
    } = require('auth0');

    let {
        value: token
    } = api.cache.get('management-token') || {};
    const {
        domain,
        clientId,
        clientSecret
    } = event.secrets || {};
    if (!token) {

        const cc = new AuthenticationClient({
            domain,
            clientId,
            clientSecret
        });

        try {
            const {
                data
            } = await cc.oauth.clientCredentialsGrant({
                scope: `update:users read:users`,
                audience: `https://${domain}/api/v2/`
            });

            token = data?.access_token;

            if (!token) {
                console.log('failed get api v2 cc token');
                return;
            }
            console.log('cache MIS m2m token!');

            const result = api.cache.set('management-token', token, {
                ttl: data.expires_in * 1000
            });

            if (result?.type === 'error') {
                console.log('failed to set the token in the cache with error code', result.code);
            }
        } catch (err) {
            console.log('failed calling cc grant', err);
            return;
        }
    }

    const client = new ManagementClient({
        domain,
        token
    });

    if (!makePrimary) {
        const user_id = token_sub;

        try {
            await client.users.link({
                id: event.user.user_id
            }, {
                user_id,
                token_provider
            });
            console.log(`link successful ${token_sub} to ${event.user.user_id}`);
        } catch (err) {
            console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
            return;
        }

        api.authentication.setPrimaryUser(event.user.user_id);

        console.log(`changed primary from  ${token_sub}to ${event.user.user_id}`);
    } else {

        const {
            user_id,
            provider
        } = event.user.identities[0];

        try {
            await client.users.link({
                id: token_sub
            }, {
                user_id,
                provider
            });
            console.log(`link successful ${token_sub} to ${user_id} of provider: ${provider}`);
        } catch (err) {
            console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
            return;
        }

        api.authentication.setPrimaryUser(token_sub);

        console.log(`changed primary from ${event.user.user_id} to ${token_sub}`);
    }
}

exports.onExecutePostLogin = async (event, api) => {


    const protocol = event?.transaction?.protocol || 'unknown';

    if (!interactive_login.test(protocol)) {
        return;
    }

    if (event.stats.logins_count > 1) {
        console.log("skipping as not the first login");
        return;
    }

    if (event.request.query.account_linking) {
        console.log("skipping as already in linking");
        return;
    }

    var existingUsers = await checkForExistingAccount(event, api, event.user.email);
    existingUsers = existingUsers.data;
    existingUsers = existingUsers.filter((t) => t.user_id != event.user.user_id);

    // remove the current user
    if (existingUsers.length > 0) {

        const crypto = require('crypto');
        const codeVerifier = crypto
            .randomBytes(60)
            .toString('hex')
            .slice(0, 128);
        const codeChallenge = crypto
            .createHash('sha256')
            .update(Buffer.from(codeVerifier))
            .digest('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');

        api.prompt.render(FORM_ID, {
            vars: {
                matching_accounts: existingUsers,
                code_challenge: codeChallenge,
                code_verifier: codeVerifier,
                target_primary: true,
                nonce: event.transaction.id
            }
        });
    } else {
        console.log("No matching users - no account linking");
    }
}

exports.onContinuePostLogin = async (event, api) => {
    console.log(`onContinuePostLogin event: ${JSON.stringify(event)}`);

    if (event.prompt.vars.code) {

        const id_token = await exchangeAndVerify(api, event?.secrets?.domain, event.request?.hostname, event.client.client_id, event.prompt.vars.code_verifier, event.prompt.vars.redirect_uri, event.prompt.vars.code, event.transaction.id);
        const id_token_provider = id_token.sub.substring(0, id_token.sub.indexOf("|"));
        console.log(id_token_provider);
        if (id_token.email_verified !== true && id_token_provider !== "sms") {
            console.log(`skipped linking, email not verified in nested tx user: ${id_token.email}`);
            return;
        }

        if (!database_sub.test(id_token.sub)) {
            api.access.deny(`invalid sub from inner tx: ${id_token.sub}`);
            return;
        }


        if (event.user.email !== id_token.email && event.prompt.vars.target_primary) {
            api.access.deny('emails do not match');
            return;
        }

        await linkAndMakePrimary(event, api, id_token.sub, id_token_provider, event.prompt.vars.target_primary);
    }
}