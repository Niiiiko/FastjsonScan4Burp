package burp.bean;

import burp.IHttpRequestResponse;

/**
 * @ClassName: Issus
 * @Auther: niko
 * @Date: 2025/2/1 19:22
 * @Description:
 */
public class Issus {
    public enum State{
        SAVE,ADD,TIMEOUT,ERROR
    }
    private String url;
    private String method;
    private String status;
    private String payload;
    private String result;
    private IHttpRequestResponse iHttpRequestResponse;
    private State state;


    public Issus() {
    }



    public Issus(String url, String method, String status, String payload, String result, IHttpRequestResponse iHttpRequestResponse, State state) {
        this.url = url;
        this.method = method;
        this.status = status;
        this.payload = payload;
        this.result = result;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.state = state;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public IHttpRequestResponse getiHttpRequestResponse() {
        return iHttpRequestResponse;
    }

    public void setiHttpRequestResponse(IHttpRequestResponse iHttpRequestResponse) {
        this.iHttpRequestResponse = iHttpRequestResponse;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }
}
