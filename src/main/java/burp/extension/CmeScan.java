package burp.extension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.bean.Issus;

import java.util.Iterator;
import java.util.List;

/**
 * @ClassName: CmeScan
 * @Auther: niko
 * @Date: 2025/2/7 22:45
 * @Description:
 */
public class CmeScan extends BaseScan{


    protected CmeScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        super(callbacks, iHttpRequestResponse, helpers);
    }

    @Override
    List<Issus> insertPayloads(Iterator<String> payloadIterator, String jsonKey) {
        IHttpRequestResponse newRequestResonse = null;
        String randCommand = null;
        while (payloadIterator.hasNext()){
            String payload = payloadIterator.next();
            if (jsonKey ==null || jsonKey.length()<=0){
                newRequestResonse = run(payload);
            }else {
                newRequestResonse = run(payload, jsonKey);
            }
            IRequestInfo response = helpers.analyzeRequest(newRequestResonse.getResponse());
            int bodyOffset = response.getBodyOffset();
            int bodylength = newRequestResonse.getResponse().length - bodyOffset;
            String responseBody = new String(response, bodyOffset, bodylength, "UTF-8");


        }
        return null;
    }
}
