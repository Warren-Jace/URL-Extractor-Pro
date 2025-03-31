# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
import os
from javax.swing import (JPanel, JTextArea, JScrollPane, JButton, JTextField, 
                       JLabel, JCheckBox, JFileChooser, JSplitPane, SwingConstants,
                       JComboBox, JSpinner, SpinnerNumberModel, BorderFactory)
from javax.swing.border import TitledBorder
from javax.swing.text import DefaultEditorKit
from java.awt import (BorderLayout, Dimension, FlowLayout, GridBagLayout, 
                     GridBagConstraints, Insets, Font, Color)
from java.util import HashSet, ArrayList
import threading
from datetime import datetime
import re
import json
from urlparse import urlparse  

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def __init__(self):
        # 初始化数据
        self.save_path = os.path.expanduser("~/Desktop/urls.txt")
        self.blacklist = set(["example.com", "test.com"])
        self.extensions = set(["js", "css", "jpg", "png", "jpg", "html"])  # 支持多种扩展名
        self.keywords = set(["jquery", "bootstrap", "angular"])
        self.url_set = HashSet()
        self.lock = threading.Lock()
        self.config_file = os.path.expanduser("~/.burp_url_extractor_config.json")
        
        # 创建UI
        self._callbacks = None
        self._helpers = None
        self._main_panel = None
        self._output = None
        self._log_output = None
        
        # 设置中文字体
        self.chinese_font = Font("Microsoft YaHei", Font.PLAIN, 12)  # 使用微软雅黑
        
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Extractor Pro")
        
        self.load_config()
        
        self._initUI()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.save_path = config.get('save_path', self.save_path)
                    self.blacklist = set(config.get('blacklist', list(self.blacklist)))
                    self.extensions = set(config.get('extensions', list(self.extensions)))
                    self.keywords = set(config.get('keywords', list(self.keywords)))
        except Exception as e:
            self._callbacks.printError("Failed to load config: {}".format(str(e)))

    def save_config(self):
        try:
            config = {
                'save_path': self.save_path,
                'blacklist': list(self.blacklist),
                'extensions': list(self.extensions),
                'keywords': list(self.keywords)
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self._callbacks.printError("Failed to save config: {}".format(str(e)))

    def _initUI(self):
        # 创建主面板
        self._main_panel = JPanel(BorderLayout(15, 15))  # 增加整体边距
        
        # 创建控制面板
        control_panel = JPanel(GridBagLayout())
        control_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0))
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 5, 5, 5)
        
        # ===== 过滤器面板 =====
        filter_panel = JPanel(GridBagLayout())
        filter_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200), 1),
                u" 过滤规则 ",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color(100, 100, 100)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        
        # 统一创建过滤选项的函数
        def create_filter_option(label_text, field_value, tooltip):
            panel = JPanel(GridBagLayout())
            panel.setBackground(Color(250, 250, 250))
            
            # 标签
            label = JLabel(label_text, SwingConstants.RIGHT)
            label.setFont(self.chinese_font)
            label.setPreferredSize(Dimension(55, 28))
            label.setForeground(Color(60, 60, 60))
            
            # 文本框
            field = JTextField(field_value)
            field.setFont(self.chinese_font)
            field.setToolTipText(tooltip)
            
            # 下拉框
            mode = JComboBox([u"禁用", u"白名单", u"黑名单"])
            mode.setFont(self.chinese_font)
            mode.setPreferredSize(Dimension(90, 28))
            mode.setBackground(Color.WHITE)
            
            # 使用GridBagLayout进行布局
            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(0, 5, 0, 5)
            
            # 添加标签
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.weightx = 0
            panel.add(label, gbc)
            
            # 添加文本框
            gbc.gridx = 1
            gbc.weightx = 1.0
            panel.add(field, gbc)
            
            # 添加下拉框
            gbc.gridx = 2
            gbc.weightx = 0
            panel.add(mode, gbc)
            
            return panel, field, mode
        
        # 创建三个过滤选项
        extension_panel, self._extension_field, self._extension_mode = create_filter_option(
            u"扩展名", ",".join(self.extensions), u"输入要过滤的扩展名，用逗号分隔，常见的有：js, css, jpg, png, html, txt")
        keyword_panel, self._keyword_field, self._keyword_mode = create_filter_option(
            u"关键字", ",".join(self.keywords), u"输入要过滤的关键字，用逗号分隔，常见的有：jquery, bootstrap, angular")
        blacklist_panel, self._blacklist_field, self._blacklist_mode = create_filter_option(
            u"域名", ", ".join(self.blacklist), u"输入要过滤的域名，用逗号分隔，常见的有：example.com, test.com")
        self._blacklist_mode.setSelectedItem(u"黑名单")
        
        # 使用GridBagLayout布局三个过滤选项
        filter_gbc = GridBagConstraints()
        filter_gbc.fill = GridBagConstraints.HORIZONTAL
        filter_gbc.insets = Insets(0, 0, 0, 10)
        filter_gbc.gridy = 0
        filter_gbc.weighty = 1.0
        
        # 添加三个过滤选项面板
        filter_gbc.gridx = 0
        filter_gbc.weightx = 0.33
        filter_panel.add(extension_panel, filter_gbc)
        
        filter_gbc.gridx = 1
        filter_gbc.weightx = 0.34
        filter_panel.add(keyword_panel, filter_gbc)
        
        filter_gbc.gridx = 2
        filter_gbc.weightx = 0.33
        filter_gbc.insets = Insets(0, 0, 0, 0)  # 最后一个组件不需要右边距
        filter_panel.add(blacklist_panel, filter_gbc)
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = GridBagConstraints.REMAINDER
        gbc.weightx = 1.0
        control_panel.add(filter_panel, gbc)
        
        # ===== 路径设置面板 =====
        path_panel = JPanel(BorderLayout(10, 0))
        path_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200), 1),
                u" 路径设置 ",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color(100, 100, 100)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        
        # 路径输入区域
        path_input_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        path_input_panel.setBackground(Color(250, 250, 250))
        
        path_label = JLabel(u"保存路径", SwingConstants.RIGHT)
        path_label.setFont(self.chinese_font)
        path_label.setPreferredSize(Dimension(65, 28))
        path_label.setForeground(Color(60, 60, 60))
        path_input_panel.add(path_label)
        
        self._path_field = JTextField(self.save_path)
        self._path_field.setFont(self.chinese_font)
        self._path_field.setEditable(False)
        self._path_field.setPreferredSize(Dimension(350, 28))
        path_input_panel.add(self._path_field)
        
        browse_button = JButton(u"浏览")
        browse_button.setFont(self.chinese_font)
        browse_button.addActionListener(self.browse_file)
        browse_button.setPreferredSize(Dimension(80, 28))
        path_input_panel.add(browse_button)
        
        path_panel.add(path_input_panel, BorderLayout.CENTER)
        
        # 按钮面板
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 0))
        button_panel.setBackground(Color(250, 250, 250))
        
        # 创建统一样式的按钮
        def create_button(text, action_listener, width=100):
            btn = JButton(text)
            btn.setFont(self.chinese_font)
            btn.addActionListener(action_listener)
            btn.setPreferredSize(Dimension(width, 28))
            return btn
        
        save_settings_button = create_button(u"保存设置", self.save_all_settings, 120)
        clear_button = create_button(u"清空URL", self.clear_output)
        clear_log_button = create_button(u"清空日志", self.clear_log)
        export_button = create_button(u"导出URL", self.export_urls)
        
        for btn in [save_settings_button, clear_button, clear_log_button, export_button]:
            button_panel.add(btn)
        
        path_panel.add(button_panel, BorderLayout.EAST)
        
        gbc.gridy = 1
        control_panel.add(path_panel, gbc)
        
        # ===== 选项设置面板 =====
        options_panel = JPanel(BorderLayout(10, 0))
        options_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200), 1),
                u" 其他选项 ",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color(100, 100, 100)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        
        # 复选框面板
        checkbox_panel = JPanel(FlowLayout(FlowLayout.LEFT, 15, 0))
        checkbox_panel.setBackground(Color(250, 250, 250))
        
        # 创建统一样式的复选框
        def create_checkbox(text, selected, tooltip):
            cb = JCheckBox(text, selected)
            cb.setFont(self.chinese_font)
            cb.setToolTipText(tooltip)
            cb.setBackground(Color(250, 250, 250))
            return cb
        
        self._save_to_file = create_checkbox(u"自动保存", True, u"自动保存URL到文件")
        self._unique_only = create_checkbox(u"去重", True, u"只保存唯一的URL")
        self._timestamp = create_checkbox(u"时间戳", False, u"添加时间戳")
        self._filter_js = create_checkbox(u"JS文件", False, u"只显示.js结尾的文件")
        self._filter_status = create_checkbox(u"状态码", False, u"过滤HTTP状态码")
        
        for cb in [self._save_to_file, self._unique_only, self._timestamp,
                  self._filter_js, self._filter_status]:
            checkbox_panel.add(cb)
        
        options_panel.add(checkbox_panel, BorderLayout.WEST)
        
        # 状态码和导出格式面板
        status_format_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 15, 0))
        status_format_panel.setBackground(Color(250, 250, 250))
        
        # 状态码输入
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        status_panel.setBackground(Color(250, 250, 250))
        
        status_label = JLabel(u"状态码", SwingConstants.RIGHT)
        status_label.setFont(self.chinese_font)
        status_label.setForeground(Color(60, 60, 60))
        status_panel.add(status_label)
        
        self._status_codes = JTextField("200,301,302", 8)
        self._status_codes.setFont(self.chinese_font)
        self._status_codes.setPreferredSize(Dimension(100, 28))
        self._status_codes.setToolTipText(u"要过滤的状态码，用逗号分隔")
        status_panel.add(self._status_codes)
        
        # 导出格式选择
        format_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        format_panel.setBackground(Color(250, 250, 250))
        
        format_label = JLabel(u"导出格式", SwingConstants.RIGHT)
        format_label.setFont(self.chinese_font)
        format_label.setForeground(Color(60, 60, 60))
        format_panel.add(format_label)
        
        self._export_format = JComboBox([u"纯文本", u"JSON", u"CSV"])
        self._export_format.setFont(self.chinese_font)
        self._export_format.setPreferredSize(Dimension(100, 28))
        format_panel.add(self._export_format)
        
        status_format_panel.add(status_panel)
        status_format_panel.add(format_panel)
        
        options_panel.add(status_format_panel, BorderLayout.EAST)
        
        gbc.gridy = 2
        control_panel.add(options_panel, gbc)
        
        # ===== 输出面板 =====
        output_panel = JPanel(BorderLayout(0, 10))
        
        # URL列表面板
        url_panel = JPanel(BorderLayout(5, 5))
        url_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200), 1),
                u" URL列表 ",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color(100, 100, 100)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        
        self._output = JTextArea()
        self._output.setFont(Font("Consolas", Font.PLAIN, 12))  # 使用等宽字体
        self._output.setEditable(False)
        self._output.setLineWrap(False)  # 关闭自动换行
        self._output.setWrapStyleWord(True)
        self._output.setBackground(Color(252, 252, 252))
        self._output.setForeground(Color(50, 50, 50))  # 设置文字颜色
        self._output.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))  # 添加内边距
        
        # 添加URL时自动换行
        # 添加URL时格式化显示
        def add_url_with_newline(url):
            # 去除URL两端的空白字符
            url = url.strip()
            if not url:
                return
                
            with self.lock:
                current_count = len(self._output.getText().split("\n"))
                if current_count > 0 and self._output.getText().strip():
                    # 添加分隔线
                    separator = "\n" + "-" * 80 + "\n"
                    self._output.append(separator)
                
                # 格式化URL显示 - 修改为Jython 2.7兼容的字符串格式化
                formatted_url = "[{0}] {1}".format(current_count + 1, url)
                self._output.append(formatted_url)
                
                # 自动滚动到最新位置
                self._output.setCaretPosition(self._output.getDocument().getLength())
        
        self.add_url_with_newline = add_url_with_newline
        
        # 使用带有更好滚动体验的滚动面板
        scroll_pane = JScrollPane(self._output, 
                                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        scroll_pane.setBorder(BorderFactory.createLineBorder(Color(230, 230, 230)))
        scroll_pane.getVerticalScrollBar().setUnitIncrement(16)  # 设置更平滑的滚动
        url_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # 日志面板
        log_panel = JPanel(BorderLayout(5, 5))
        log_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200), 1),
                u" 日志信息 ",
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color(100, 100, 100)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        
        self._log_output = JTextArea()
        self._log_output.setFont(self.chinese_font)
        self._log_output.setEditable(False)
        self._log_output.setLineWrap(True)
        self._log_output.setWrapStyleWord(True)
        self._log_output.setBackground(Color(252, 252, 252))
        log_document = self._log_output.getDocument()
        log_document.putProperty(DefaultEditorKit.EndOfLineStringProperty, "\n")
        
        log_scroll = JScrollPane(self._log_output)
        log_scroll.setBorder(BorderFactory.createLineBorder(Color(230, 230, 230)))
        log_panel.add(log_scroll, BorderLayout.CENTER)
        
        # 垂直分割面板
        split_pane_vertical = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane_vertical.setBorder(None)
        split_pane_vertical.setTopComponent(url_panel)
        split_pane_vertical.setBottomComponent(log_panel)
        split_pane_vertical.setDividerLocation(400)
        split_pane_vertical.setResizeWeight(0.7)
        
        output_panel.add(split_pane_vertical, BorderLayout.CENTER)
        
        # 主分割面板
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split_pane.setBorder(None)
        main_split_pane.setTopComponent(control_panel)
        main_split_pane.setBottomComponent(output_panel)
        main_split_pane.setDividerLocation(280)
        main_split_pane.setResizeWeight(0.4)
        
        self._main_panel.add(main_split_pane, BorderLayout.CENTER)

    def export_urls(self, event):
        try:
            if not self._output.getText().strip():
                self.log_message(u"没有URL导出")
                return
                
            export_format = self._export_format.getSelectedItem()
            urls = [line.strip() for line in self._output.getText().split("\n") if line.strip()]
            
            if export_format == u"JSON":
                data = {"urls": urls}
                with open(self.save_path, "w") as f:
                    json.dump(data, f, indent=2)
            elif export_format == u"CSV":
                with open(self.save_path, "w") as f:
                    f.write("URL\n")
                    for url in urls:
                        f.write(u"{}\n".format(url))
            else:  # Plain Text
                with open(self.save_path, "w") as f:
                    f.write("\n".join(urls))
                    
            self.log_message(u"URL导出成功，格式为：{}，路径为：{}".format(export_format, self.save_path))
        except Exception as e:
            self.log_message(u"导出错误：{}".format(str(e)), True)

    def browse_file(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            self.save_path = chooser.getSelectedFile().getAbsolutePath()
            self._path_field.setText(self.save_path)
            self.save_config()

    def clear_output(self, event):
        self._output.setText("")
        self.url_set.clear()
        self.log_message(u"URL输出清空")

    def clear_log(self, event):
        self._log_output.setText("")
        self.log_message(u"日志清空")

    def save_all_settings(self, event):
        """保存所有设置"""
        try:
            # 更新保存路径
            self.save_path = self._path_field.getText()
            
            # 更新黑名单
            self.blacklist = {domain.strip().lower() for domain in self._blacklist_field.getText().split(",") if domain.strip()}
            
            # 更新扩展名列表
            self.extensions = {ext.strip().lower() for ext in self._extension_field.getText().split(",") if ext.strip()}
            
            # 更新关键字列表
            self.keywords = {kw.strip().lower() for kw in self._keyword_field.getText().split(",") if kw.strip()}
            
            # 保存所有配置
            self.save_config()
            
            # 显示更新信息
            self.log_message(u"设置保存成功：")
            self.log_message(u"- 保存路径：{}".format(self.save_path))
            self.log_message(u"- 黑名单：{}".format(", ".join(sorted(self.blacklist))))
            self.log_message(u"- 扩展名：{} ({} 模式)".format(
                ", ".join(sorted(self.extensions)),
                self._extension_mode.getSelectedItem()
            ))
            self.log_message(u"- 关键字：{} ({} 模式)".format(
                ", ".join(sorted(self.keywords)),
                self._keyword_mode.getSelectedItem()
            ))
            
        except Exception as e:
            self.log_message(u"保存设置错误：{}".format(str(e)), True)

    def log_message(self, message, is_error=False):
        # 如果消息以 "URL:" 开头，提取 URL 部分并单独显示到URL面板
        if message.startswith(u"URL:"):
            # 使用正则表达式提取 URL 和状态码（如果存在）
            match = re.match(r"URL: (.*?)(?:\s+\[Status: (\d+)\])?$", message)
            if match:
                url = match.group(1).strip()
                status = match.group(2)
                # 格式化输出到URL面板
                timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._timestamp.isSelected() else ""
                if status:
                    url_output = timestamp + url + " [" + status + "]"
                else:
                    url_output = timestamp + url
                
                # 使用我们的统一方法添加URL
                self.add_url_with_newline(url_output)
        
        # 所有消息都记录到日志面板，确保每条消息独占一行
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        
        # 处理消息格式，确保每行只显示一个操作
        message_lines = message.split("\n")
        for line in message_lines:
            if line.strip():  # 只处理非空行
                # 添加分隔线使显示更清晰
                if self._log_output.getText().strip():
                    self._log_output.append("\n")  # 确保新日志前有空行
                log_line = timestamp + line.strip() + "\n"
                self._log_output.append(log_line)
        
        # 滚动到最新位置
        self._log_output.setCaretPosition(self._log_output.getDocument().getLength())
        
        if is_error:
            self._callbacks.printError(message)
        else:
            self._callbacks.printOutput(message)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:  # 只处理响应
                return
            
            # 获取URL
            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            
            # 检查是否为空或重复
            if not url or (self._unique_only.isSelected() and url in self.url_set):
                return
            
            # 获取域名
            domain = urlparse(url).netloc.lower()
            
            # 检查域名过滤
            mode = self._blacklist_mode.getSelectedItem()
            if mode != u"禁用" and self.blacklist and domain:
                is_match = any(blacklisted.lower().strip() in domain 
                             for blacklisted in self.blacklist if blacklisted.strip())
                if (mode == u"黑名单" and is_match) or (mode == u"白名单" and not is_match):
                    self.log_message(u"URL被过滤（{} 模式：{}）：{}".format(mode, domain, url))
                    return
            
            # 检查扩展名过滤 - 更严格的匹配逻辑
            if self._extension_mode.getSelectedItem() != u"禁用":
                path = urlparse(url).path.lower()
                # 获取最后一个点后面的部分作为扩展名
                ext = path.split('.')[-1] if '.' in path and not path.endswith('/') else ''
                
                # 严格检查扩展名是否在配置列表中
                if ext:
                    mode = self._extension_mode.getSelectedItem()
                    is_match = ext in self.extensions
                    
                    # 白名单模式：只允许配置的扩展名通过
                    if mode == u"白名单" and not is_match:
                        self.log_message(u"URL被过滤（白名单模式，扩展名不匹配：{}）：{}".format(ext, url))
                        return
                    # 黑名单模式：阻止配置的扩展名通过
                    elif mode == u"黑名单" and is_match:
                        self.log_message(u"URL被过滤（黑名单模式，扩展名：{}）：{}".format(ext, url))
                        return
                else:
                    # 白名单模式下，没有扩展名的URL应该被过滤
                    if self._extension_mode.getSelectedItem() == u"白名单":
                        self.log_message(u"URL被过滤（白名单模式，无扩展名）：{}".format(url))
                        return
            
            # 检查关键字过滤
            if self._keyword_mode.getSelectedItem() != u"禁用":
                mode = self._keyword_mode.getSelectedItem()
                is_match = any(keyword.lower().strip() in url.lower() 
                             for keyword in self.keywords if keyword.strip())
                if (mode == u"黑名单" and is_match) or (mode == u"白名单" and not is_match):
                    self.log_message(u"URL被过滤（{} 模式，关键字匹配）：{}".format(mode, url))
                    return
            
            # 检查JS文件过滤
            if self._filter_js.isSelected() and not url.lower().endswith('.js'):
                return
            
            # 检查状态码过滤
            if self._filter_status.isSelected():
                status_code = str(self._helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode())
                valid_codes = [code.strip() for code in self._status_codes.getText().split(',')]
                if status_code not in valid_codes:
                    return
            
            # 添加URL到URL面板
            self.add_url_with_newline(url)
            self.url_set.add(url)
            
            # 自动保存
            if self._save_to_file.isSelected():
                self.save_url(url)
                
        except Exception as e:
            self.log_message(u"处理URL时出错：{}".format(str(e)), True)

    def save_url(self, url):
        try:
            # 确保保存路径的目录存在
            save_dir = os.path.dirname(self.save_path)
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)
                
            # 确保文件路径是绝对路径
            if not os.path.isabs(self.save_path):
                self.save_path = os.path.abspath(self.save_path)
            
            with self.lock:
                try:
                    with open(self.save_path, "a") as f:
                        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._timestamp.isSelected() else ""
                        f.write(timestamp + url + "\n")
                        f.flush()  # 立即写入磁盘
                except Exception as write_error:
                    error_msg = u"保存URL错误：{} (路径：{})".format(str(write_error), self.save_path)
                    self.log_message(error_msg, True)
                    
        except Exception as e:
            error_msg = u"保存URL错误：{} (路径：{})".format(str(e), self.save_path)
            self.log_message(error_msg, True)

    def getTabCaption(self):
        return u"URL Extractor Pro"

    def getUiComponent(self):
        return self._main_panel
