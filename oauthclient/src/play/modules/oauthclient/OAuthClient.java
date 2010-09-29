package play.modules.oauthclient;

import oauth.signpost.OAuthProvider;
import oauth.signpost.basic.DefaultOAuthProvider;
import play.Logger;
import play.libs.WS.WSRequest;
import play.mvc.results.Redirect;

public class OAuthClient implements IOAuthClient {

	private String requestURL;
	private String accessURL;
	private String authorizeURL;
	private String consumerKey;
	private String consumerSecret;

	private WSOAuthConsumer consumer;
	private OAuthProvider provider;

	public OAuthClient(String requestURL, String accessURL, String authorizeURL, String consumerKey, String consumerSecret) {
		this.requestURL = requestURL;
		this.accessURL = accessURL;
		this.authorizeURL = authorizeURL;
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
	}


  private WSOAuthConsumer getConsumer(ICredentials cred) {
		if (consumer == null) {
			consumer = new WSOAuthConsumer(
				consumerKey,
				consumerSecret);
			consumer.setTokenWithSecret(cred.getToken(), cred.getSecret());
		}
		return consumer;
	}

  private OAuthProvider getProvider() {
		if (provider == null) {
			provider = new DefaultOAuthProvider(
					requestURL,
					accessURL,
					authorizeURL);
			provider.setOAuth10a(true);
		}
		return provider;
	}

	// Authentication

	/* (non-Javadoc)
   * @see play.modules.oauthclient.IOAuthClient#authenticate(play.modules.oauthclient.ICredentials, java.lang.String)
   */
  public void authenticate(ICredentials cred, String callbackURL) throws Exception {
		throw new Redirect(retrieveRequestToken(cred, callbackURL));
	}

	/**
   * Retrieve the request token.
   * @param cred the ICredentials where the oauth token and oauth secret will be set.
   * @param callbackURL: the URL the user should be redirected after he grants the rights to our app
   * @return the URL on the provider's site that we should redirect the user
   */
  private String retrieveRequestToken(ICredentials cred, String callbackURL) throws Exception {
		Logger.debug("Consumer key: " + getConsumer(cred).getConsumerKey());
		Logger.debug("Consumer secret: " + getConsumer(cred).getConsumerSecret());
		Logger.debug("Token before request: " + getConsumer(cred).getToken());
		String authUrl = getProvider().retrieveRequestToken(getConsumer(cred), callbackURL);
		Logger.info("[retrieveRequestToken] Token after request: " + getConsumer(cred).getToken());
		cred.setToken(consumer.getToken());
		cred.setSecret(consumer.getTokenSecret());
		cred.gotRequestToken();
		return authUrl;
	}

  /**
   * Retrieve the access token.
   * @param cred the ICredentials with the request token and secret already set (using retrieveRequestToken).
   * The access token and secret will be set these.
   * @return the URL on the provider's site that we should redirect the user
   * @see retrieveRequestToken
   */
  public void retrieveAccessToken(ICredentials cred, String verifier) throws Exception {
		Logger.debug("Token before retrieve: " + getConsumer(cred).getToken());
		Logger.debug("Verifier: " + verifier);
		getProvider().retrieveAccessToken(getConsumer(cred), verifier);
		Logger.info("[retrieveAccessToken] Token after request: " + getConsumer(cred).getToken());
		cred.setToken(consumer.getToken());
		cred.setSecret(consumer.getTokenSecret());
		cred.gotAccessToken();
	}

	// Signing requests

	/* (non-Javadoc)
   * @see play.modules.oauthclient.IOAuthClient#sign(play.modules.oauthclient.ICredentials, java.lang.String)
   */
  public String sign(ICredentials user, String url) throws Exception {
		return getConsumer(user).sign(url);
	}

	/* (non-Javadoc)
   * @see play.modules.oauthclient.IOAuthClient#sign(play.modules.oauthclient.ICredentials, play.libs.WS.WSRequest, java.lang.String)
   */
  public WSRequest sign(ICredentials user, WSRequest request, String method) throws Exception {
		return getConsumer(user).sign(request, method);
	}

}
