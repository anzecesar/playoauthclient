package play.modules.oauthclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import oauth.signpost.OAuthProvider;
import play.Logger;
import play.libs.WS.WSRequest;
import play.mvc.results.Redirect;

public class OAuth2Client implements IOAuthClient {
  private String authorizeURL;
  private String accessURL;
  private String clientSecret;
  private String clientId;
  
  public OAuth2Client(String authorizeURL, String accessURL, String clientId, String clientSecret) {
    this.authorizeURL = authorizeURL;
    this.accessURL = accessURL;
    this.clientSecret = clientSecret;
    this.clientId = clientId;
  }
  
  /**
   * The callback extepcts parameter 'code'
   */
  public void authenticate(ICredentials cred, String callbackURL)
      throws Exception {
    StringBuilder sb = new StringBuilder(authorizeURL);
    String delim = authorizeURL.contains("?") ? "&" : "?";
    sb.append(delim).append("client_id=").append(clientId).append("&redirect_uri=");
    sb.append(URLEncoder.encode(callbackURL, "UTF-8"));
    
    Logger.debug("OAuth2 authenticate URL %s", sb.toString());
    
    throw new Redirect(sb.toString());

  }

  /**
   * 
   * @param cred
   * @param verifier
   * @param callback The same callback used with 'authenticate'
   * @throws Exception
   */
  public void retrieveAccessToken(ICredentials cred, String verifier, String callback)
      throws Exception {
    Logger.debug("ACCESS TOKEN");
    
    StringBuilder sb = new StringBuilder(accessURL).append("?code=").append(verifier);
    sb.append("&redirect_uri=").append(callback);
    sb.append("&client_id=").append(clientId).append("&client_secret=").append(clientSecret);
    
    //throw new Redirect(sb.toString());
    
    URL url = new URL(sb.toString());
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setDoOutput(false);
    connection.setRequestMethod("GET");
    connection.connect();
    String token = convertStreamToString(connection.getInputStream());
    token = token.substring(token.indexOf("=") + 1, token.indexOf("&"));
    Logger.debug("access token %s", token);
    cred.setToken(token);
    cred.gotAccessToken();
    
//    StringBuilder sb = new StringBuilder(accessURL).append("?type=client_cred");
//    sb.append("&client_id=").append(clientId).append("&client_secret=").append(clientSecret);
//    URL url = new URL(sb.toString());
//    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//    connection.setDoOutput(false);
//    connection.setRequestMethod("GET");
//    connection.connect();
//    String token = convertStreamToString(connection.getInputStream());
//    token = token.substring(token.indexOf("=") + 1);
//    Logger.debug("access token %s", token);
//    //secret not needed I think :]
//    cred.setToken(token);
//    cred.gotAccessToken();
  }

  public String sign(ICredentials user, String url) throws Exception {
    StringBuilder sb = new StringBuilder(url);
    sb.append("?access_token=").append(user.getToken());
    return sb.toString();
  }

  public WSRequest sign(ICredentials user, WSRequest request, String method)
      throws Exception {
    // TODO Auto-generated method stub
    return null;
  }
  
  private static String convertStreamToString(InputStream is) throws IOException {
    if (is != null) {
      StringBuilder sb = new StringBuilder();
      String line;

      try {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
        while ((line = reader.readLine()) != null) {
          sb.append(line).append("\n");
        }
      } finally {
        is.close();
      }
      return sb.toString();
    } else {       
      return "";
    }
  }

}
