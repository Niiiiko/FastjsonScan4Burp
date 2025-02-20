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
            // 暂时不考虑对cookie进行fastjson检测
            if (parameter.getType() == IParameter.PARAM_URL||parameter.getType() == IParameter.PARAM_BODY){
                value = parameter.getValue();
                TargetInfo targetInfo = isJson(parameter.getName(),value);
                if (targetInfo.isFlag()){
                    return targetInfo;
                }
            }
        }
        return new TargetInfo(false, null);
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
        TargetInfo targetInfo = new TargetInfo(result, key);
        return targetInfo;
    }

    // post content-type:json
    public TargetInfo isContypeJson(){
        String s = String.valueOf(requestInfo.getContentType());
        if ("4".equals(s)){
            return new TargetInfo(true,null);
        }
        return new TargetInfo(false,null);

    }

}

