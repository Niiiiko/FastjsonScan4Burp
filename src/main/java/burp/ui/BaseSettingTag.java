package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.utils.YamlReader;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BaseSettingTag {
    private YamlReader yamlReader;

    private JCheckBox isStartBox;
    private JCheckBox isStartLowPercept;
    private JCheckBox isStartBypass;
    private JCheckBox isScanGetJsonBox;
    private JCheckBox isScanPostJsonBox;
    private JCheckBox isScanCookieJsonBox;
    private JCheckBox isScanJsonBox;
    private JCheckBox isScanBodyJsonBox;
    private IBurpExtenderCallbacks callbacks;
    private JCheckBox isStartCmdEchoExtensionBox;
    private JCheckBox isStartRemoteCmdExtensionBox;
    private String dnslogName;
    private String messageType;
    private ScanQueueTag scanQueueTag;


    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader,ScanQueueTag scanQueueTag) {
        this.callbacks = callbacks;
        JPanel baseSetting = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.yamlReader = yamlReader;
        this.scanQueueTag = scanQueueTag;
        // 添加下拉框
//          # DnsLogCn = http://dnslog.cn的接口
//  # BurpDnsLog = burp自带的dnslog接口
//  # CeyeDnslog = http://ceye.io的接口
//  # EyesDnslog = https://eyes.sh的接口
        String[] options = {"DnsLogCn", "BurpDnsLog", "CeyeDnslog","EyesDnslog"}; // 下拉框选项
        JComboBox<String> comboBox = addComboBox(baseSetting, c, "dnslog平台选择:", options);

        String[] options2 = {"ALL", "INFO", "VULN"}; // 下拉框选项
        JComboBox<String> comboBox2 = addComboBox2(baseSetting, c, "UI显示选择:", options2);
        this.input1_1(baseSetting, c);
        this.input1_2(baseSetting, c);
        this.input1_3(baseSetting, c);
        this.input3_1(baseSetting, c);
        this.input3_2(baseSetting, c);
        this.input3_3(baseSetting, c);
        this.input3_4(baseSetting, c);
        this.input4_1(baseSetting, c);
        this.input4_2(baseSetting, c);
        tabs.addTab("基本设置", baseSetting);
    }

    private void input1_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_1_1 = new JLabel("基础设置");
        br_lbl_1_1.setForeground(new Color(255, 89, 18));
        br_lbl_1_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_1_1.getFont().getSize() + 2));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 1;
        baseSetting.add(br_lbl_1_1, c);
    }

    private void input1_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartBox = new JCheckBox("插件-启动", this.yamlReader.getBoolean("isStart"));
        this.isStartBox.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 2;
        baseSetting.add(this.isStartBox, c);
    }

    private void input1_3(JPanel baseSetting, GridBagConstraints c) {
        this.isStartBypass = new JCheckBox("Bypass waf", this.yamlReader.getBoolean("isStartBypass"));
        this.isStartBypass.setFont(new Font("Serif", Font.PLAIN, this.isStartBypass.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 3;
        baseSetting.add(this.isStartBypass, c);
    }
    private JComboBox<String> addComboBox(JPanel baseSetting, GridBagConstraints c, String labelText, String[] options) {
        // 创建标签
        JLabel label = new JLabel(labelText);
        label.setForeground(new Color(255,89,18));
        label.setFont(new Font("Serif", Font.PLAIN, label.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 10;
        c.anchor = GridBagConstraints.WEST;
        baseSetting.add(label, c);
        String yamlDnsname = this.yamlReader.getString("dnsLogModule.provider");
        this.setDnslogName(yamlDnsname);
        int id = 0;
        for (int i = 0; i < options.length; i++) {
            if (options[i].equals(yamlDnsname)){
                id = i;
                break;
            }
        }
        // 创建下拉框
        JComboBox<String> comboBox = new JComboBox<>(options);
        comboBox.setSelectedIndex(id); // 默认选中第一个选项
        c.gridx =  0;
        c.gridy = 11;
        baseSetting.add(comboBox, c);

//         添加事件监听器
        comboBox.addActionListener(e -> {
            String selectedOption = (String) comboBox.getSelectedItem();
            callbacks.printOutput("用户选择了: " + selectedOption);
            setDnslogName(selectedOption);
        });

        return comboBox;
    }

    private void input3_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_3_1 = new JLabel("被动扫描模块配置");
        br_lbl_3_1.setForeground(new Color(255, 89, 18));
        br_lbl_3_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_3_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 5;
        baseSetting.add(br_lbl_3_1, c);
    }

    private void input3_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartLowPercept = new JCheckBox("低感知fastjson探测", this.yamlReader.getBoolean("application.lowPerceptionScan.config.isStart"));
        this.isStartLowPercept.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 6;
        baseSetting.add(this.isStartLowPercept, c);
    }
    private void input3_3(JPanel baseSetting, GridBagConstraints c) {
        this.isStartCmdEchoExtensionBox = new JCheckBox("命令回显扩展-启动", this.yamlReader.getBoolean("application.cmdEchoExtension.config.isStart"));
        this.isStartCmdEchoExtensionBox.setFont(new Font("Serif", Font.PLAIN, this.isStartCmdEchoExtensionBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 7;
        baseSetting.add(this.isStartCmdEchoExtensionBox, c);
    }

    private void input3_4(JPanel baseSetting, GridBagConstraints c) {
        this.isStartRemoteCmdExtensionBox = new JCheckBox("远程命令扩展-启动", this.yamlReader.getBoolean("application.remoteCmdExtension.config.isStart"));
        this.isStartRemoteCmdExtensionBox.setFont(new Font("Serif", Font.PLAIN, this.isStartRemoteCmdExtensionBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 8;
        baseSetting.add(this.isStartRemoteCmdExtensionBox, c);
    }

    private void input4_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_3_1 = new JLabel("ui界面模块");
        br_lbl_3_1.setForeground(new Color(255, 89, 18));
        br_lbl_3_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_3_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 12;
        baseSetting.add(br_lbl_3_1, c);
    }
    private void input4_2(JPanel baseSetting, GridBagConstraints c) {
        // 清空按钮
        JButton clearBtn = new JButton("清空扫描队列");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    baseSetting,
                    "确认清空所有扫描记录？\n此操作不可逆！",
                    "警告",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );

            if (confirm == JOptionPane.YES_OPTION) {
                SwingUtilities.invokeLater(() -> {
                    scanQueueTag.clearAllRecords();
                    callbacks.printOutput("[操作日志] 扫描队列已清空");
                });
            }
        });

        // 布局参数
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 13;
        c.fill = GridBagConstraints.HORIZONTAL;
        baseSetting.add(clearBtn, c);
    }
    private JComboBox<String> addComboBox2(JPanel baseSetting, GridBagConstraints c, String labelText, String[] options) {
        // 创建标签
        JLabel label = new JLabel(labelText);
        label.setForeground(new Color(255,89,18));
        label.setFont(new Font("Serif", Font.PLAIN, label.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 10;
        c.anchor = GridBagConstraints.WEST;
        baseSetting.add(label, c);
        String uiMessage = this.yamlReader.getString("message");
        this.setMessageType(uiMessage);
        int id = 0;
        for (int i = 0; i < options.length; i++) {
            if (options[i].equals(uiMessage)){
                id = i;
                break;
            }
        }
        // 创建下拉框
        JComboBox<String> comboBox = new JComboBox<>(options);
        comboBox.setSelectedIndex(id); // 默认选中第一个选项
        c.gridx =  0;
        c.gridy = 14;
        baseSetting.add(comboBox, c);

//         添加事件监听器
        comboBox.addActionListener(e -> {
            String selectedOption = (String) comboBox.getSelectedItem();
            callbacks.printOutput("用户选择了: " + selectedOption);
            setMessageType(selectedOption);
        });

        return comboBox;
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }


    public Boolean isStartLowPercept() {
        return this.isStartLowPercept.isSelected();
    }

    public Boolean isStartBypass() {
        return this.isStartBypass.isSelected();
    }
    public void setDnslogName(String name) {
        this.dnslogName = name;
    }
    public String getDnslogName() {
        return dnslogName;
    }

    public void setMessageType(String name) {
        this.messageType = name;
    }
    public String getMessageType() {
        return messageType;
    }

    public Boolean isStartCmdEchoExtension() {
        return this.isStartCmdEchoExtensionBox.isSelected();
    }

    public Boolean isStartRemoteCmdExtension() {
        return this.isStartRemoteCmdExtensionBox.isSelected();
    }
}