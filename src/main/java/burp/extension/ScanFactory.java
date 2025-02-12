package burp.extension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.extension.scan.BaseScan;
import burp.IHttpRequestResponse;
import java.lang.reflect.Constructor;

public class ScanFactory {

    public static BaseScan createScan(String extendName,IHttpRequestResponse iHttpRequestResponse,IExtensionHelpers helpers,IBurpExtenderCallbacks callbacks) throws ClassNotFoundException, NoSuchMethodException {
        if (extendName == null || extendName.length()<=0){
            throw new IllegalArgumentException("无法找到调用的插件名称");
        }

        Class<?> clazz = Class.forName("burp.extension.scan.impl." + extendName);
        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(
                IBurpExtenderCallbacks.class,
                IHttpRequestResponse.class,
                IExtensionHelpers.class
        );
        try {
            return (BaseScan) declaredConstructor.newInstance(callbacks, iHttpRequestResponse, helpers);
        } catch (Exception e) {
            throw new ClassNotFoundException();
        }

    }
}
