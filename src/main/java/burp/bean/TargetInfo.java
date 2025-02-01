package burp.bean;

/**
 * @ClassName: TargetInfo
 * @Auther: niko
 * @Date: 2025/1/17 16:11
 * @Description:
 */
public class TargetInfo {
    private boolean flag;
    private String json;
    private String key;
    private Integer id;
    private String method;

    public TargetInfo(boolean flag, String json, String key, Integer id) {
        this.flag = flag;
        this.json = json;
        this.key = key;
        this.id = id;
    }

    public boolean isFlag() {
        return flag;
    }

    public void setFlag(boolean flag) {
        this.flag = flag;
    }

    public String getJson() {
        return json;
    }

    public void setJson(String json) {
        this.json = json;
    }

    public String getKey() {
        return key;
    }

    public void setkey(String key) {
        this.key = key;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
}
