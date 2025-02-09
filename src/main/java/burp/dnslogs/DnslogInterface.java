package burp.dnslogs;

public interface DnslogInterface {
    String getBodyContent();

    String getAllContent();

    String getExtensionName();

    String getRandomDnsUrl();

    String getRandomPredomain();
}
