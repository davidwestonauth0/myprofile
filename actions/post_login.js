/**
* Handler that will be called during the execution of a PostLogin flow.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
exports.onExecutePostLogin = async (event, api) => {

  const FORM_ID = 'ap_i7AK7g6X4ymghxCxJVzoJF';
    const interactive_login = new RegExp('^oidc-');
      const protocol = event?.transaction?.protocol || 'unknown';

  if (!interactive_login.test(protocol)) {
      return;
  }

  if (event.transaction && event.transaction.requested_scopes && event.transaction.requested_scopes.includes("myprofile")) {
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
      current_session: event.session.id,
      client_id: event.secrets.CLIENT_ID,
      client_secret: event.secrets.CLIENT_SECRET,
      auth0_domain: "https://"+event.secrets.DOMAIN,
      code_challenge: codeChallenge,
      code_verifier: codeVerifier,
      target_primary: "false",
      nonce: event.transaction.id
    }
  });
  }
}


async function exchangeAndVerify(api, domain, custom_domain, client_id, code_verifier, redirect_uri, code, nonce) {

    const axios = require('axios');

    console.log(`exchanging code: ${code}`);

    const {data: {id_token}} =
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

        const {value: signingKey} = api.cache.get(`key-${header.kid}`) || {};

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
            algorithms: 'RS256'
        }, (err, decoded) => {
            if (err) reject(err);
            else resolve(decoded);
        });
    });
}

async function linkAndMakePrimary(event, api, primary_sub, linkDetails) {

    if (primary_sub===event.user.user_id){
        console.log("Skipping as already linked");
        return;
    }

    if (!linkDetails.primary) {
        console.log(`linking ${primary_sub} under ${event.user.user_id}`);
    }
    else {
        console.log(`linking ${event.user.user_id} under ${primary_sub}`);
    }

    const {ManagementClient, AuthenticationClient} = require('auth0');

    let {value: token} = api.cache.get('management-token') || {};
    const CLIENT_SECRET = event.secrets.CLIENT_SECRET;
    const CLIENT_ID = event.secrets.CLIENT_ID;
    const DOMAIN = event.secrets.DOMAIN;

    if (!token) {
        const cc = new AuthenticationClient({domain: DOMAIN, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});

        try {
            const {data} = await cc.oauth.clientCredentialsGrant({scope: `update:users read:users`, audience: `https://${DOMAIN}/api/v2/`});
            token = data?.access_token;

            if (!token) {
                console.log('failed get api v2 cc token');
                return;
            }
            console.log('cache MIS m2m token!');

            const result = api.cache.set('management-token', token, {ttl: data.expires_in * 1000});

            if (result?.type === 'error') {
                console.log('failed to set the token in the cache with error code', result.code);
            }
        } catch (err) {
            console.log('failed calling cc grant', err);
            return;
        }
    }

    const client = new ManagementClient({domain: DOMAIN, token});

    if (linkDetails.target_primary=="false") {
        const provider = linkDetails.target_provider;
        const user_id = primary_sub;

        try {
            await client.users.link({id: event.user.user_id}, {user_id, provider});
            console.log(`link successful ${primary_sub} to ${event.user.user_id}`);
        } catch (err) {
            console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
            return;
        }

        api.authentication.setPrimaryUser(event.user.user_id);

        console.log(`changed primary from  ${primary_sub}to ${event.user.user_id}`);
    } else {

        const {user_id, provider} = event.user.identities[0];

        try {
            await client.users.link({id: primary_sub}, {user_id, provider});
            console.log(`link successful ${primary_sub} to ${user_id} of provider: ${provider}`);
        } catch (err) {
            console.log(`unable to link, no changes. error: ${JSON.stringify(err)}`);
            return;
        }

        api.authentication.setPrimaryUser(primary_sub);

        console.log(`changed primary from ${event.user.user_id} to ${primary_sub}`);
    }
}



/**
* Handler that will be invoked when this action is resuming after an external redirect. If your
* onExecutePostLogin function does not perform a redirect, this function can be safely ignored.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
  const database_sub = new RegExp('^auth0|');

exports.onContinuePostLogin = async (event, api) => {
  console.log(`onContinuePostLogin event: ${JSON.stringify(event)}`);

  if (event.prompt.vars.code) {

    const id_token = await exchangeAndVerify(api, event?.secrets?.DOMAIN, event.request?.hostname, event.client.client_id, event.prompt.vars.code_verifier, event.prompt.vars.redirect_uri, event.prompt.vars.code, event.transaction.id);

    if (id_token.email_verified !== true && event.prompt.vars.target_connection !== "sms") {
        console.log(`skipped linking, email not verified in nested tx user: ${id_token.email}`);
        return;
    }

    if (!database_sub.test(id_token.sub)) {
        api.access.deny(`invalid sub from inner tx: ${id_token.sub}`);
        return;
    }


    if (event.user.email !== id_token.email && event.prompt.vars.target_primary=="true") {
        api.access.deny('emails do not match');
        return;
    }

    await linkAndMakePrimary(event, api, id_token.sub, event.prompt.vars);
  }

}