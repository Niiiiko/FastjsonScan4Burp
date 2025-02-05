package burp.bean;

/**
 * @ClassName: TargetInfo
 * @Auther: niko
 * @Date: 2025/1/17 16:11
 * @Description:
 */
public class TargetInfo {
    private boolean flag;
    private String key;

    public TargetInfo(boolean flag, String key) {
        this.flag = flag;
        this.key = key;
    }

    public boolean isFlag() {
        return flag;
    }

    public String getKey() {
        return key;
    }
}
