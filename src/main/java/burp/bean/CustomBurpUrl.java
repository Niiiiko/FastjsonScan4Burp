package burp.bean;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class CustomBurpUrl {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;

    private IHttpRequestResponse requestResponse;

    public CustomBurpUrl(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.requestResponse = requestResponse;
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    /**
     * 获取-请求协议
     *
     * @return
     */
    public String getRequestProtocol() {
        return this.requestResponse.getHttpService().getProtocol();
    }

    /**
     * 获取-请求主机
     *
     * @return
     */
    public String getRequestHost() {
        return this.requestResponse.getHttpService().getHost();
    }

    /**
     * 获取-请求端口
     *
     * @return
     */
    public int getRequestPort() {
        return this.requestResponse.getHttpService().getPort();
    }

    /**
     * 获取-请求路径
     *
     * @return
     */
    public String getRequestPath() {
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getPath();
    }

    /**
     * 获取-请求参数
     *
     * @return
     */
    public String getRequestQuery() {
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getQuery();
    }

    /**
     * 获取-请求域名名称
     *
     * @return
     */
    public String getRequestDomainName() {
        if (this.getRequestPort() == 80 || this.getRequestPort() == 443) {
            return this.getRequestProtocol() + "://" + this.getRequestHost();
        } else {
            return this.getRequestProtocol() + "://" + this.getRequestHost() + ":" + this.getRequestPort();
        }
    }
    /**
     * 获取-获取请求方式名称
     *
     * @return
     */
    public String getRequestMethod() {
        String method = this.helpers.analyzeRequest(requestResponse).getMethod();
        return method;
    }

    /**
     * 获取-获取http请求url
     *
     * @return
     */
    public URL getHttpRequestUrl() {
        try {
            if (this.getRequestQuery() == null) {
                return new URL(this.getRequestDomainName() + this.getRequestPath());
            } else {
                return new URL(this.getRequestDomainName() + this.getRequestPath() + "?" + this.getRequestQuery());
            }
        } catch (MalformedURLException e) {
            e.printStackTrace(this.stderr);
        }
        return null;
    }
    /**
     * 获取-获取请求header头
     *
     * @return
     */
    public List<String> getHttpRequestHeaders(){
        List<String> headers = helpers.analyzeRequest(this.requestResponse).getHeaders();
        return headers;
    }
    /**
     * 获取-获取请求参数
     *
     * @return
     */
    public List<IParameter> getHttpRequestParameters() {
        List<IParameter> parameters = helpers.analyzeRequest(requestResponse).getParameters();
        return parameters;
    }

    /**
     * 获取- 请求体body
     *
     * @return
     */
    public String getHttpRequestBody(){
        int bodyOffset = helpers.analyzeRequest(requestResponse.getRequest()).getBodyOffset();
        int length = requestResponse.getRequest().length - bodyOffset;
        try {
            return new String(requestResponse.getRequest(),bodyOffset,length,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * 获取-获取http响应体body
     *
     * @return
     */
    public String getHttpResponseBody() {
        byte[] response = this.requestResponse.getResponse();
        if (response == null){
            return "";
        }
        int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
        int length = response.length - bodyOffset;
        try {
            String body = new String(response, bodyOffset, length, "UTF-8");
            return body;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * 获取-获取http响应体状态
     *
     * @return
     */
    public String getHttpResponseStatus() {
        return String.valueOf(helpers.analyzeResponse(this.requestResponse.getResponse()).getStatusCode());
    }


}