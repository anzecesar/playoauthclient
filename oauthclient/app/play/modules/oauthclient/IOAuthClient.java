package play.modules.oauthclient;

import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import play.libs.WS.WSRequest;

public interface IOAuthClient {

  public abstract void authenticate(ICredentials cred, String callbackURL)
      throws Exception;

  /**
   * Sign the url with the OAuth tokens for the user. This method can only be used for GET requests.
   * @param url
   * @return
   * @throws OAuthMessageSignerException
   * @throws OAuthExpectationFailedException
   * @throws OAuthCommunicationException
   */
  public abstract String sign(ICredentials user, String url) throws Exception;

  public abstract WSRequest sign(ICredentials user, WSRequest request,
      String method) throws Exception;

}