package burp.extension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.util.List;

/**
 * @ClassName: RemoteCmd
 * @Auther: niko
 * @Date: 2025/1/20 17:25
 * @Description:
 */
public class RemoteCmd {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private List<String> payloads;

    public RemoteCmd(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, List<String> payloads) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = payloads;
    }


}
