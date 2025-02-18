package burp.bean;

public enum ScanResultType {
    PAYLOADS_FIND("[+] Payload find out"),
    MAY_FASTJSON("[+] Maybe use fastjson"),
    IS_FASTJSON("[+] Fastjson with Network"),
    NO_FASTJSON("[+] Maybe no fastjson"),
    VERSION_INFO("[+] version: %s"),
    LIBRARY_FOUND("[+] library: %s"),
    NOT_FOUND("[-] Payload not find"),
    DNS_ERROR("[-] Dnslog error"),
    WAIT_CONFIRM("[=] Task timeout");
    private final String messageFormat;

    ScanResultType(String messageFormat) {
        this.messageFormat = messageFormat;
    }

    public String format(Object... args) {
        return String.format(this.messageFormat, args);
    }
}