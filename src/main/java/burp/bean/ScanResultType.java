package burp.bean;

public enum ScanResultType {
    PAYLOADS_FIND("[+] Payload find out"),
    VERSION_INFO("[+] version: %s"),
    LIBRARY_FOUND("[+] library: %s"),
    NOT_FOUND("[-] Payload not find"),
    DNS_ERROR("[-] Dnslog error");
    private final String messageFormat;

    ScanResultType(String messageFormat) {
        this.messageFormat = messageFormat;
    }

    public String format(Object... args) {
        return String.format(this.messageFormat, args);
    }
}