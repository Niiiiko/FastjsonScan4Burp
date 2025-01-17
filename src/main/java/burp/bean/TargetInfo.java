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
    private String payload;
    private Integer id;

    public TargetInfo(boolean flag, String json, String payload, Integer id) {
        this.flag = flag;
        this.json = json;
        this.payload = payload;
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

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }
}
