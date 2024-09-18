/**
* Handler that will be called during the execution of a PostLogin flow.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
exports.onExecutePostLogin = async (event, api) => {

  const FORM_ID = 'ap_i7AK7g6X4ymghxCxJVzoJF';

  if (event.transaction.requested_scopes.includes("myprofile")) {
//pass a client authorized to management api
  api.prompt.render(FORM_ID, {
    vars: {
      current_session: event.session.id,
      client_id: event.secrets.CLIENT_ID,
      client_secret: event.secrets.CLIENT_SECRET,
      auth0_domain: "https://"+event.secrets.DOMAIN
    }
  });
  }
}




/**
* Handler that will be invoked when this action is resuming after an external redirect. If your
* onExecutePostLogin function does not perform a redirect, this function can be safely ignored.
*
* @param {Event} event - Details about the user and the context in which they are logging in.
* @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
*/
exports.onContinuePostLogin = async (event, api) => {
  // Add your logic after completing the form
}