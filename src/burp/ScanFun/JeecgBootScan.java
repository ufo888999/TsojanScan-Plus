package burp.ScanFun;

import burp.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;

public class JeecgBootScan {

    private static final String[] JEECG_PATHS = {
        "/jeecg-boot/",
        "/jmreport/",
        "/jmreport/queryFieldBySql",
        "/jeecg-boot/jmreport/queryFieldBySql"
    };

    public static IHttpRequestResponse Scan(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        if (!isJeecgBoot(baseRequestResponse, helpers)) {
            return null;
        }
        IHttpRequestResponse sqliResult = scanSQLInjection(baseRequestResponse, callbacks, helpers);
        if (sqliResult != null) {
            return sqliResult;
        }

        IHttpRequestResponse unauthResult = scanUnauthorizedAccess(baseRequestResponse, callbacks, helpers);
        if (unauthResult != null) {
            return unauthResult;
        }
        IHttpRequestResponse infoLeakResult = scanInfoLeak(baseRequestResponse, callbacks, helpers);
        if (infoLeakResult != null) {
            return infoLeakResult;
        }

        return null;
    }

    private static boolean isJeecgBoot(IHttpRequestResponse baseRequestResponse, IExtensionHelpers helpers) {
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String path = url.getPath();
        for (String jeecgPath : JEECG_PATHS) {
            if (path.contains(jeecgPath)) {
                return true;
            }
        }
        return false;
    }

    public static IHttpRequestResponse scanSQLInjection(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        byte[] request = baseRequestResponse.getRequest();
        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        String payload = "{\"sql\":\"select 1 from dual\"}";
        
        List<String> newHeaders = new ArrayList<>(headers);

        if (!headers.get(0).startsWith("POST")) {
            newHeaders.set(0, headers.get(0).replace("GET", "POST"));
        }

        boolean hasContentType = false;
        for (int i = 0; i < newHeaders.size(); i++) {
            if (newHeaders.get(i).toLowerCase().startsWith("content-type:")) {
                newHeaders.set(i, "Content-Type: application/json;charset=UTF-8");
                hasContentType = true;
            }
        }
        if (!hasContentType) {
            newHeaders.add("Content-Type: application/json;charset=UTF-8");
        }

        byte[] newRequest = helpers.buildHttpMessage(newHeaders, payload.getBytes(StandardCharsets.UTF_8));
        IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        
        String response = new String(newRequestResponse.getResponse(), StandardCharsets.UTF_8);
        // Check for successful execution or specific Jeecg response
        if (response.contains("success") && response.contains("true") && !response.contains("error")) {
             return newRequestResponse;
        }
        return null;
    }

    public static IHttpRequestResponse scanUnauthorizedAccess(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        byte[] request = baseRequestResponse.getRequest();
        IRequestInfo reqInfo = helpers.analyzeRequest(request);
        List<String> headers = reqInfo.getHeaders();

        List<String> newHeaders = new ArrayList<>();
        for (String header : headers) {
            String lower = header.toLowerCase();
            if (!lower.startsWith("cookie:") && !lower.startsWith("authorization:") && !lower.startsWith("token:") && !lower.startsWith("x-access-token:")) {
                newHeaders.add(header);
            }
        }

        if (!newHeaders.get(0).startsWith("POST")) {
            newHeaders.set(0, newHeaders.get(0).replace("GET", "POST"));
        }

        String payload = "{\"sql\":\"select 1 from dual\"}";
        
        boolean hasContentType = false;
        for (int i = 0; i < newHeaders.size(); i++) {
             if (newHeaders.get(i).toLowerCase().startsWith("content-type:")) {
                 newHeaders.set(i, "Content-Type: application/json;charset=UTF-8");
                 hasContentType = true;
             }
        }
        if(!hasContentType) newHeaders.add("Content-Type: application/json;charset=UTF-8");

        byte[] newRequest = helpers.buildHttpMessage(newHeaders, payload.getBytes(StandardCharsets.UTF_8));
        IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        
        String response = new String(newRequestResponse.getResponse(), StandardCharsets.UTF_8);
        
        // If we get a success response without credentials
        if (response.contains("success") && response.contains("true")) {
            return newRequestResponse;
        }
        return null;
    }

    public static IHttpRequestResponse scanInfoLeak(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        String response = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
        // Keywords for sensitive info in JSON responses
        String[] keywords = {
            "\"password\"", 
            "\"salt\"", 
            "\"phone\"", 
            "\"idCard\"", 
            "\"bankCard\""
        };
        
        for (String keyword : keywords) {
            if (response.contains(keyword)) {
                 return baseRequestResponse;
            }
        }
        return null;
    }
}
