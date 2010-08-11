package play.modules.oauthclient;

public interface ICredentials {

	public void setToken(String token);

	public String getToken();

	public void setSecret(String secret);

	public String getSecret();
	
	/**
	 * Callback, invoked after request token was received.
	 */
	public void gotRequestToken();

	/**
   * Callback, invoked after access token was received.
   */
  public void gotAccessToken();
}
