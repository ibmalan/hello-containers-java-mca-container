package wasdev.sample.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import okhttp3.*;
import org.json.JSONObject;
//import java.util.Base64;
import net.iharder.Base64;
import java.util.logging.Logger;

/**
 * Servlet implementation class SimpleServlet
 */
@WebServlet("/SimpleServlet")
public class SimpleServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;


    private static final Logger logger = Logger.getLogger(SimpleServlet.class.getName());
    private static final OkHttpClient client = new OkHttpClient();

    private static final String clientId = "ced326ac-8759-4d04-99fe-9e0f7ab69c48";
    private static final String clientSecret = "OTRiZTNlMjktYzg5Yy00OTRkLThhNjYtMzliZTU4YTU5ZDQx";
    private static final String callbackUri = "http://hello-containers-java-mca-container.mybluemix.net/oauth/callback";
    private static final String authzEndpoint = "https://mobileclientaccess.ng.bluemix.net/oauth/v2/authorization";
    private static final String tokenEndpoint = "https://mobileclientaccess.ng.bluemix.net/oauth/v2/token";
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    }
    
    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("Incoming request :: " + request.getRequestURL() + "/" + request.getQueryString());
        logger.info("Redirecting to MCA for authorization");

        if (request.getRequestURI().contains("/login")){
            onLogin(request, response);
        } else if (request.getRequestURI().contains("/callback")){
            onCallback(request, response);
        } else if (request.getRequestURI().contains("/logout")){
            onLogout(request, response);
        } else {
            response.sendError(404, "Not Found");
        }
    }

    private void onLogin(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onLogin");
        String authzUrl = authzEndpoint + "?response_type=code";
        authzUrl += "&client_id=" + clientId;
        authzUrl += "&redirect_uri=" + callbackUri;
        response.sendRedirect(authzUrl);
    }


    private void onCallback(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onCallback");
        String grantCode = request.getQueryString().split("=")[1];

        JSONObject body = new JSONObject();
        try {
            body.put("grant_type", "authorization_code");
            body.put("client_id", clientId);
            body.put("redirect_uri", callbackUri);
            body.put("code", grantCode);
        } catch (Throwable t){}


        String credentials = Credentials.basic(clientId, clientSecret);
        Request req = new Request.Builder()
                .url(tokenEndpoint)
                .header("Authorization", credentials)
                .post(RequestBody.create(MediaType.parse("application/json"), body.toString()))
                .build();


        Response res = client.newCall(req).execute();
        JSONObject parsedBody = new JSONObject(res.body().string());
        String accessToken = parsedBody.getString("access_token");
        String idToken = parsedBody.getString("id_token");

//        byte[] decodedIdTokenPayload = Base64.getUrlDecoder().decode(idToken.split("\\.")[1]);
        String idTokenPayload = idToken.split("\\.")[1];
        byte[] decodedIdTokenPayload = Base64.decode(idTokenPayload, Base64.URL_SAFE);
        JSONObject decodedIdentityToken = new JSONObject(new String(decodedIdTokenPayload));
        logger.info("decodedToken :: " + new String(decodedIdTokenPayload));
        JSONObject userIdentity = decodedIdentityToken.getJSONObject("imf.user");

        JSONObject authData = new JSONObject();
        authData.put("accessToken", accessToken);
        authData.put("idToken", idToken);
        authData.put("userIdentity", userIdentity);

        request.getSession().setAttribute("mca", authData);

        response.sendRedirect("/");
    }


    private void onLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.info("onLogout");
        request.getSession().setAttribute("mca", null);
        response.sendRedirect("/");
    }
    
}
