package burp.extension.scan.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.extension.scan.BaseScan;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static burp.utils.Customhelps.tabFormat;

/**

 * @ClassName: DetectLibrary 
 * @Auther: niko
 * @Date: 2025/2/11 16:50
 * @Description: 
 */
public class libraryDetect extends BaseScan {

    public libraryDetect(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        super(callbacks, iHttpRequestResponse, helpers);
    }

    @Override
    public List<Issus> insertPayloads(String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        boolean flag = true;
        String payload = yamlReader.getString("application.detectLibraryExtension.config.libraryPayloads");
        List<String> libraries = yamlReader.getStringList("application.detectLibraryExtension.config.libraries");
        Iterator<String> libraryIterator = libraries.iterator();
        Issus issus = null;
        List<Issus> issuses = new ArrayList<>();
        IHttpRequestResponse newRequestResonse = null;

        while (libraryIterator.hasNext()){
            String library = libraryIterator.next();
            if (jsonKey == null || jsonKey.length()<=0){
                newRequestResonse = run(payload.replace("libraries",library));
            }else {
                newRequestResonse = run(payload.replace("libraries",library),jsonKey);
            }
            String bodyContent = customBurpUrl.getHttpResponseBody();
            // 捕获api.ceye 503异常，避免导致issus未更新

            if(bodyContent == null|| bodyContent.length()<=0){
                continue;
            }
            bodyContent = bodyContent.toLowerCase();
            if (bodyContent.contains(library.toLowerCase())) {
                // 碰到能检测出多个payload，则更新第一个issus的状态为[+]，后续payload直接add [+]issus进去
                if (flag){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            tabFormat(ScanResultType.LIBRARY_FOUND,library),
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            getExtensionName(),
                            customBurpUrl.getRequestMethod(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            tabFormat(ScanResultType.LIBRARY_FOUND,library),
                            newRequestResonse,
                            Issus.State.ADD);
                    issuses.add(issus);
                }
            }
        }
        return issuses;
    }

    @Override
    public String getExtensionName() {
        return "libraryDetect";
    }
}
