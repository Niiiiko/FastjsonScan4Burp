package burp.dnslogs;

import burp.IBurpExtenderCallbacks;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * @ClassName: DnsLog
 * @Auther: niko
 * @Date: 2025/2/9 14:35
 * @Description:
 */
public class DnsLog {
    private DnslogInterface dnsLog;

    public DnsLog(IBurpExtenderCallbacks callbacks, String callClassName) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if (callClassName == null || callClassName.length() <= 0) {
            throw new IllegalArgumentException("DnsLog模块-请输入要调用的dnsLog插件");
        }
        Class c = Class.forName("burp.dnslogs.impl." + callClassName);
        Constructor cConstructor = c.getConstructor(IBurpExtenderCallbacks.class);
        this.dnsLog = (DnslogInterface) cConstructor.newInstance(callbacks);

        if (this.dnsLog.getExtensionName().isEmpty()) {
            throw new IllegalArgumentException("请为该DnsLog扩展-设置扩展名称");
        }
    }

    public DnslogInterface run(){
        return this.dnsLog;
    }


}
