package burp.utils;

import burp.*;
import burp.bean.TargetInfo;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;

/**
 * @ClassName: FindJsons
 * @Auther: niko
 * @Date: 2025/1/17 15:55
 * @Description:
 */
public class FindJsons{
    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private IRequestInfo requestInfo;
    private Boolean isJson;
    private String json;


    public FindJsons(IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse) {
        this.helpers = helpers;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
    }
    // GET/POST 方法，params是否带有fastjson
    public TargetInfo isParamsJson()  {
        String value = null;
        List<IParameter> parameters = requestInfo.getParameters();
        for(IParameter parameter : parameters ){
            value = parameter.getValue();
            TargetInfo targetInfo = isJson(parameter.getName(),value);
            if (targetInfo.isFlag()){
                return targetInfo;
            }
        }
        return isJson(value);
    }

    private TargetInfo isJson(String parameter, String str) {
        String key = null;
        boolean result = false;
        if (str != null && !str.isEmpty()) {
            try {
                str = URLDecoder.decode(str, "utf-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            str = str.trim();
            if(str.indexOf("{") !=-1 && str.lastIndexOf("}")!=-1){
                key = parameter;
                result = true;
            }else if (str.indexOf("[") !=-1 && str.lastIndexOf("]")!=-1){
                key = parameter;
                result = true;
            }
        }
        TargetInfo targetInfo = new TargetInfo(result, json, key, null);
        return targetInfo;
    }

    public TargetInfo isJson(String str) {
        String json = null;
        boolean result = false;
        if (str != null && !str.isEmpty()) {
            try {
                str = URLDecoder.decode(str, "utf-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            str = str.trim();
            if(str.indexOf("{") !=-1 && str.lastIndexOf("}")!=-1){
                json = str.substring(str.indexOf("{"),str.lastIndexOf("}")+1);
                result = true;
            }else if (str.indexOf("[") !=-1 && str.lastIndexOf("]")!=-1){
                json = str.substring(str.indexOf("["),str.lastIndexOf("]")+1);
                result = true;
            }
        }
        TargetInfo targetInfo = new TargetInfo(result, json, null, null);
        return targetInfo;
    }

    // post content-type:json
    public TargetInfo isContypeJson(){
        String s = String.valueOf(requestInfo.getContentType());
        String httpRequestBody = null;
        if ("4".equals(s)){
            int bodyOffset = requestInfo.getBodyOffset();
            int length = iHttpRequestResponse.getRequest().length - bodyOffset;
            try {
                httpRequestBody = new String(iHttpRequestResponse.getRequest(), bodyOffset, length, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            return new TargetInfo(true,httpRequestBody,null,null);
        }
        return new TargetInfo(false,httpRequestBody,null,null);

    }


    public static void main(String[] args) {
        String test = "faoing{\"aa\":1}FAF";

        String json = test.substring(test.indexOf("{"), test.lastIndexOf("}")+1);
        System.out.println(json);
        System.out.println(test.lastIndexOf("}"));
        System.out.println(test);
    }

}

