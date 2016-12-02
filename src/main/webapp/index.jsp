<%@ page import="org.json.JSONObject" %><%--
  Created by IntelliJ IDEA.
  User: antona
  Date: 11/21/16
  Time: 08:10
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title>Web App MCA Demo Java Container Testing</title>
  </head>
  <body>

    Hello! Please login first!

    <%
        JSONObject mcaContext = (JSONObject) request.getSession().getAttribute("mca");
        if (mcaContext != null){
            JSONObject userIdentity = mcaContext.getJSONObject("userIdentity");
            String displayName = userIdentity.getString("displayName");
            String pictureUrl = "https://image.freepik.com/free-icon/user-silhouette_318-79814.png";
            if (userIdentity.getJSONObject("attributes").has("picture")){
                JSONObject pictureData = userIdentity.getJSONObject("attributes").getJSONObject("picture");
                pictureUrl = pictureData.getJSONObject("data").getString("url");
            }

    %>
            <p>Hello <%=displayName%></p>
            <p><img src="<%=pictureUrl%>"/></p>

            <br><a href="/oauth/logout">Logout</a>
    <%
        } else {
    %>
            <br><a href="/oauth/login">Login</a>
    <%
        }
    %>

    <br><br>

  </body>
</html>
