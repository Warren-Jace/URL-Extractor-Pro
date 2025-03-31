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
from java.awt.event import ActionListener, ItemListener
from javax.swing import SwingUtilities
from java.awt.event import ItemEvent

class BurpExtender(IBurpExtender, IHttpListener, ITab, ActionListener, ItemListener):
    def __init__(self):
        # 初始化数据
        self.save_path = os.path.expanduser("~/Desktop/urls.txt")
        self.blacklist = set(["example.com", "test.com"])
        self.extensions = set(["js", "css", "jpg", "png", "jpg", "html"])  # 支持多种扩展名
        self.keywords = set(["jquery", "bootstrap", "angular"])
        self.url_set = HashSet()
        self.lock = threading.Lock()
        self.config_file = os.path.expanduser("~/.burp_url_extractor_config.json")
        
        # 默认静态文件后缀
        self.static_extensions = {"js", "css", "png", "jpg", "gif", "exe", "ttf", "jpeg"}
        
        # Cached settings for performance
        self._cached_save_path = self.save_path
        self._cached_blacklist = set()
        self._cached_blacklist_mode = u"黑名单" # Default mode
        self._cached_extensions = set()
        self._cached_extension_mode = u"禁用" # Default mode
        self._cached_keywords = set()
        self._cached_keyword_mode = u"禁用" # Default mode
        self._cached_status_codes = set()
        self._cached_status_codes_mode = u"禁用" # Default mode
        self._cached_static_extensions = set()
        self._cached_unique_only = True
        self._cached_save_to_file = True
        self._cached_timestamp = False
        
        # 创建UI
        self._callbacks = None
        self._helpers = None
        self._main_panel = None
        self._output = None
        self._log_output = None
        
        # 设置中文字体
        self.chinese_font = Font("Microsoft YaHei", Font.PLAIN, 12)  # 使用微软雅黑
        
        # 添加主题配置
        self.current_theme = u"明亮"  # 使用 Unicode 字符串
        self.themes = {
            u"明亮": {  # 使用 Unicode 字符串作为键
                "background": Color(252, 252, 252),
                "foreground": Color(50, 50, 50),
                "panel": Color(250, 250, 250),
                "border": Color(200, 200, 200),
                "button": Color(240, 240, 240)
            },
            u"暗黑": {  # 使用 Unicode 字符串作为键
                "background": Color(45, 45, 45),
                "foreground": Color(220, 220, 220),
                "panel": Color(60, 60, 60),
                "border": Color(80, 80, 80),
                "button": Color(70, 70, 70)
            }
        }
        
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Extractor Pro")
        
        # Load configuration first
        self.load_config()
        
        # Initialize UI (this creates components)
        self._initUI()
        
        # Now update cache with potentially loaded/default UI values
        self._update_cached_settings() # Initial cache population
        
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._callbacks.printOutput(u"URL Extractor Pro loaded successfully.")

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                if os.path.getsize(self.config_file) == 0:
                    self._callbacks.printError("Config file is empty, using default settings")
                    return
                    
                with open(self.config_file, 'rb') as f:
                    content = f.read().decode('utf-8')
                    if not content.strip():
                        self._callbacks.printError("Config file is empty, using default settings")
                        return
                        
                    config = json.loads(content)
                    self._load_config_values(config)
                    
        except ValueError as ve:
            self._callbacks.printError("Invalid JSON in config file, creating new one")
            self.save_config()
        except Exception as e:
            self._callbacks.printError("Failed to load config: {} - using default settings".format(str(e)))

    def _load_config_values(self, config):
        """加载配置值"""
        self.save_path = config.get('save_path', self.save_path)
        self.blacklist = set(config.get('blacklist', list(self.blacklist)))
        self.extensions = set(config.get('extensions', list(self.extensions)))
        self.keywords = set(config.get('keywords', list(self.keywords)))
        self.static_extensions = set(config.get('static_extensions', list(self.static_extensions)))
        self.current_theme = config.get('theme', self.current_theme)

    def save_config(self):
        try:
            # 确保配置目录存在
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            config = {
                'save_path': self.save_path,
                'blacklist': list(self.blacklist),
                'extensions': list(self.extensions),
                'keywords': list(self.keywords),
                'static_extensions': list(self.static_extensions),
                'theme': self.current_theme  # 不需要额外编码
            }
            
            # 使用临时文件保存配置
            temp_file = self.config_file + '.tmp'
            with open(temp_file, 'wb') as f:  # 使用 'wb' 模式
                json_str = json.dumps(config, ensure_ascii=False, indent=2)
                f.write(json_str.encode('utf-8'))  # 明确编码为 UTF-8
                f.flush()
                os.fsync(f.fileno())
            
            # 重命名临时文件为正式配置文件
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
            os.rename(temp_file, self.config_file)
            
        except Exception as e:
            self._callbacks.printError("Failed to save config: {}".format(str(e)))

    def _initUI(self):
        self._main_panel = JPanel(BorderLayout(15, 15))

        # 创建并添加控制面板 (此时组件已创建，但监听器未添加)
        control_panel = self._create_control_panel()

        # 创建并添加输出面板
        output_panel = self._create_output_panel()

        # 主分割面板
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, True, control_panel, output_panel) # Continuous layout
        main_split_pane.setBorder(None)
        main_split_pane.setDividerLocation(280) # 根据需要调整初始分割位置
        main_split_pane.setResizeWeight(0.3) # 调整权重，控制面板占 30%

        self._main_panel.add(main_split_pane, BorderLayout.CENTER)

        # --- 在所有UI组件创建完成后，统一添加 ItemListener ---
        self._add_item_listeners()

        # 初始化后应用当前主题
        self.apply_theme(self.current_theme)

    def _create_control_panel(self):
        """创建包含所有设置选项的控制面板"""
        control_panel = JPanel(GridBagLayout())
        # control_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0)) # 边距由主面板或父容器控制

        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridwidth = GridBagConstraints.REMAINDER
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 10, 0) # 面板间距

        # 添加过滤器面板 (创建时不再添加监听器)
        gbc.gridy = 0
        # 保存 filter_panel 引用，以便 apply_theme 使用
        self.filter_panel = self._create_filter_panel()
        control_panel.add(self.filter_panel, gbc)

        # 添加选项设置面板 (创建时不再添加监听器)
        gbc.gridy = 1
        # 保存 options_panel 引用，以便 apply_theme 使用
        self.options_panel = self._create_options_panel()
        control_panel.add(self.options_panel, gbc)

        return control_panel

    def _create_filter_panel(self):
        """创建过滤规则面板"""
        filter_panel = JPanel(GridBagLayout())
        # 保存引用以便 apply_theme 更新边框
        # self.filter_panel = filter_panel # 移动到 _create_control_panel 中赋值
        filter_panel.setBorder(self._create_titled_border(u" 过滤规则 "))

        def create_filter_option(label_text, field_value, tooltip):
            panel = JPanel(GridBagLayout())
            label = JLabel(label_text, SwingConstants.RIGHT)
            label.setFont(self.chinese_font)
            label.setPreferredSize(Dimension(55, 28))
            field = JTextField(field_value)
            field.setFont(self.chinese_font)
            field.setToolTipText(tooltip)
            mode = JComboBox([u"禁用", u"白名单", u"黑名单"])
            mode.setFont(self.chinese_font)
            mode.setPreferredSize(Dimension(90, 28))
            # mode.addItemListener(self) # <--- 移除此行

            # 保存子面板引用以便 apply_theme 设置标签颜色 (如果需要)
            if label_text == u"扩展名": self.extension_panel = panel
            elif label_text == u"关键字": self.keyword_panel = panel
            elif label_text == u"域名": self.blacklist_panel = panel
            elif label_text == u"状态码": self.status_code_panel = panel

            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(0, 5, 0, 5)
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.weightx = 0
            panel.add(label, gbc)
            gbc.gridx = 1
            gbc.weightx = 1.0
            panel.add(field, gbc)
            gbc.gridx = 2
            gbc.weightx = 0
            panel.add(mode, gbc)

            return panel, field, mode
        # ... (创建过滤选项不变) ...
        extension_panel, self._extension_field, self._extension_mode = create_filter_option(
            u"扩展名", ",".join(self.extensions), u"输入要过滤的扩展名，用逗号分隔")
        keyword_panel, self._keyword_field, self._keyword_mode = create_filter_option(
            u"关键字", ",".join(self.keywords), u"输入要过滤的关键字，用逗号分隔")
        blacklist_panel, self._blacklist_field, self._blacklist_mode = create_filter_option(
            u"域名", ", ".join(self.blacklist), u"输入要过滤的域名，用逗号分隔")
        status_code_panel, self._status_codes_field, self._status_codes_mode = create_filter_option(
            u"状态码", "200,301,302", u"输入要过滤的状态码，用逗号分隔")

        # 设置默认模式
        if self.blacklist: # 确保 blacklist 不是 None 或空
            loaded_blacklist_mode = config.get('blacklist_mode', u"黑名单") if 'config' in locals() and isinstance(config, dict) else u"黑名单" # 从配置加载或默认
            self._blacklist_mode.setSelectedItem(loaded_blacklist_mode)
        # 为其他下拉框也加载配置或设置默认值（如果需要）
        # self._extension_mode.setSelectedItem(...)
        # self._keyword_mode.setSelectedItem(...)
        # self._status_codes_mode.setSelectedItem(...)

        # ... (布局过滤选项不变) ...
        filter_gbc = GridBagConstraints()
        filter_gbc.fill = GridBagConstraints.HORIZONTAL
        filter_gbc.insets = Insets(5, 5, 5, 10) # 调整内边距
        filter_gbc.gridy = 0
        filter_gbc.weighty = 1.0
        filter_gbc.gridx = 0
        filter_gbc.weightx = 0.25
        filter_panel.add(extension_panel, filter_gbc)
        filter_gbc.gridx = 1
        filter_panel.add(keyword_panel, filter_gbc)
        filter_gbc.gridx = 2
        filter_panel.add(blacklist_panel, filter_gbc)
        filter_gbc.gridx = 3
        filter_gbc.insets = Insets(5, 5, 5, 5) # 最后一个右边距调整
        filter_panel.add(status_code_panel, filter_gbc)

        return filter_panel

    def _create_options_panel(self):
        """创建其他选项面板"""
        options_panel = JPanel(BorderLayout())
        # 保存引用以便 apply_theme 更新边框
        # self.options_panel = options_panel # 移动到 _create_control_panel 中赋值
        options_panel.setBorder(self._create_titled_border(u" 其他选项 "))

        # 保存 options_content 引用以便 apply_theme 使用
        self.options_content = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        # ... (创建路径、静态后缀、主题、导出格式不变) ...
        path_label = self._create_label(u"保存路径", 65)
        self.options_content.add(path_label)
        self._path_field = JTextField(self.save_path, 30)
        self._path_field.setFont(self.chinese_font)
        self._path_field.setEditable(False)
        self.options_content.add(self._path_field)
        browse_button = self._create_button(u"浏览", self.browse_file, 80)
        self.options_content.add(browse_button)

        static_ext_label = self._create_label(u"静态后缀", 65)
        self.options_content.add(static_ext_label)
        self._static_ext_field = JTextField(",".join(self.static_extensions), 15)
        self._static_ext_field.setFont(self.chinese_font)
        self._static_ext_field.setToolTipText(u"静态文件后缀，逗号分隔，用于路径去重")
        self.options_content.add(self._static_ext_field)

        theme_label = self._create_label(u"主题模式", 65)
        self.options_content.add(theme_label)
        self._theme_mode = JComboBox([u"明亮", u"暗黑"])
        self._theme_mode.setFont(self.chinese_font)
        self._theme_mode.setPreferredSize(Dimension(80, 28))
        self._theme_mode.setSelectedItem(self.current_theme)
        self._theme_mode.addActionListener(self.change_theme) # 这个监听器不依赖其他组件，可以保留
        self.options_content.add(self._theme_mode)

        # 复选框 (创建时不添加监听器)
        self._save_to_file = self._create_checkbox(u"自动保存", True, u"自动保存URL到文件")
        self._unique_only = self._create_checkbox(u"去重", True, u"URL去重(静态文件按路径)")
        self._timestamp = self._create_checkbox(u"时间戳", False, u"日志和保存时添加时间戳")
        self.options_content.add(self._save_to_file)
        self.options_content.add(self._unique_only)
        self.options_content.add(self._timestamp)
        # 移除这里的 ItemListener 添加
        # self._save_to_file.addItemListener(self)
        # self._unique_only.addItemListener(self)
        # self._timestamp.addItemListener(self)

        format_label = self._create_label(u"导出格式", 65)
        self.options_content.add(format_label)
        self._export_format = JComboBox([u"TXT", u"JSON", u"CSV"])
        self._export_format.setFont(self.chinese_font)
        self._export_format.setPreferredSize(Dimension(80, 28))
        self.options_content.add(self._export_format)

        # ... (创建按钮不变) ...
        save_settings_button = self._create_button(u"保存设置", self.save_all_settings, 90)
        clear_button = self._create_button(u"清空URL", self.clear_output, 90)
        clear_log_button = self._create_button(u"清空日志", self.clear_log, 90)
        export_button = self._create_button(u"导出URL", self.export_urls, 90)
        self.options_content.add(save_settings_button)
        self.options_content.add(clear_button)
        self.options_content.add(clear_log_button)
        self.options_content.add(export_button)

        options_panel.add(self.options_content, BorderLayout.CENTER)
        return options_panel

    def _create_output_panel(self):
        """创建包含URL列表和日志的输出面板"""
        output_panel = JPanel(BorderLayout(0, 10))

        # URL列表面板
        url_panel = JPanel(BorderLayout(5, 5))
        url_panel.setBorder(self._create_titled_border(u" URL列表 "))
        self._output = JTextArea()
        self._output.setFont(Font("Consolas", Font.PLAIN, 12))
        self._output.setEditable(False)
        self._output.setLineWrap(False)
        url_scroll_pane = JScrollPane(self._output,
                                     JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, # 修改为 AS_NEEDED
                                     JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        url_scroll_pane.getVerticalScrollBar().setUnitIncrement(16)
        url_panel.add(url_scroll_pane, BorderLayout.CENTER)
        self.url_panel = url_panel # 保存引用以便更新边框颜色
        self.url_scroll_pane = url_scroll_pane # 保存引用以便更新边框颜色

        # 日志面板
        log_panel = JPanel(BorderLayout(5, 5))
        log_panel.setBorder(self._create_titled_border(u" 日志信息 "))
        self._log_output = JTextArea()
        self._log_output.setFont(self.chinese_font)
        self._log_output.setEditable(False)
        self._log_output.setLineWrap(True)
        self._log_output.setWrapStyleWord(True)
        log_document = self._log_output.getDocument()
        log_document.putProperty(DefaultEditorKit.EndOfLineStringProperty, "\n")
        log_scroll = JScrollPane(self._log_output)
        log_panel.add(log_scroll, BorderLayout.CENTER)
        self.log_panel = log_panel # 保存引用以便更新边框颜色
        self.log_scroll = log_scroll # 保存引用以便更新边框颜色

        # 垂直分割面板
        split_pane_vertical = JSplitPane(JSplitPane.VERTICAL_SPLIT, True, url_panel, log_panel) # Continuous layout
        split_pane_vertical.setBorder(None)
        split_pane_vertical.setDividerLocation(400) # 初始位置
        split_pane_vertical.setResizeWeight(0.7) # URL列表占70%
        output_panel.add(split_pane_vertical, BorderLayout.CENTER)

        return output_panel

    # --- Helper methods for creating UI elements ---
    def _create_label(self, text, width):
        """创建标准标签"""
        label = JLabel(text, SwingConstants.RIGHT)
        label.setFont(self.chinese_font)
        label.setPreferredSize(Dimension(width, 28))
        # label.setForeground(Color(60, 60, 60)) # 由主题控制
        return label

    def _create_button(self, text, action_listener, width):
        """创建标准按钮"""
        btn = JButton(text)
        btn.setFont(self.chinese_font)
        btn.addActionListener(action_listener)
        btn.setPreferredSize(Dimension(width, 28))
        # btn.setBackground(...) # 由主题控制
        return btn

    def _create_checkbox(self, text, selected, tooltip):
        """创建标准复选框"""
        cb = JCheckBox(text, selected)
        cb.setFont(self.chinese_font)
        cb.setToolTipText(tooltip)
        # cb.setBackground(Color(250, 250, 250)) # 由主题控制
        return cb

    def _create_titled_border(self, title):
        """创建带标题的边框"""
        # 边框颜色和标题颜色应由主题动态设置
        # 这里只创建结构，颜色在 apply_theme 中设置
        return BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY), # 临时颜色，会被主题覆盖
                title,
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color.DARK_GRAY # 临时颜色
            ),
            BorderFactory.createEmptyBorder(5, 5, 5, 5) # 内边距
        )

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
            self.save_path = self._path_field.getText()
            self.blacklist = self._get_filtered_set(self._blacklist_field)
            self.extensions = self._get_filtered_set(self._extension_field)
            self.keywords = self._get_filtered_set(self._keyword_field)
            self.static_extensions = self._get_filtered_set(self._static_ext_field)
            self.save_config()
            self._log_settings_update()
        except Exception as e:
            self.log_message(u"保存设置错误：{}".format(str(e)), True)

    def _get_filtered_set(self, field):
        """从文本框获取过滤后的集合"""
        return {item.strip().lower() for item in field.getText().split(",") if item.strip()}

    def _log_settings_update(self):
        """记录设置更新信息"""
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
        self.log_message(u"- 静态后缀：{}".format(", ".join(sorted(self.static_extensions))))

    def log_message(self, message, is_error=False):
        # 如果消息以 "URL:" 开头，提取 URL 部分并单独显示到URL面板
        if message.startswith(u"URL:"):
            # 使用正则表达式提取 URL 和状态码（如果存在）
            match = re.match(r"URL: (.*?)(?:\s+\[Status: (\d+)\])?$", message)
            if match:
                url = match.group(1).strip()
                status = match.group(2)
                # 使用缓存的时间戳设置
                timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._cached_timestamp else ""
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
        # 使用 cached settings 提高性能
        if messageIsRequest or not self._cached_save_path: # 如果未设置保存路径，也提前返回
            return

        try:
            # 获取URL和状态码
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl().toString()
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            status_code = str(response_info.getStatusCode())

            if not url:
                return

            parsed_url = urlparse(url)
            path = parsed_url.path.lower()
            domain = parsed_url.netloc.lower()

            # 1. 状态码过滤
            if self._cached_status_codes_mode != u"禁用":
                is_match = status_code in self._cached_status_codes
                # 白名单: 不匹配则过滤; 黑名单: 匹配则过滤
                if (self._cached_status_codes_mode == u"白名单" and not is_match) or \
                   (self._cached_status_codes_mode == u"黑名单" and is_match):
                    # self.log_message(u"URL被过滤 (状态码 {} 模式: {}): {}".format(self._cached_status_codes_mode, status_code, url)) # 可选日志
                    return

            # 2. 域名过滤
            if self._cached_blacklist_mode != u"禁用" and self._cached_blacklist and domain:
                is_match = any(blacklisted in domain for blacklisted in self._cached_blacklist)
                if (self._cached_blacklist_mode == u"黑名单" and is_match) or \
                   (self._cached_blacklist_mode == u"白名单" and not is_match):
                    # self.log_message(u"URL被过滤 (域名 {} 模式: {}): {}".format(self._cached_blacklist_mode, domain, url)) # 可选日志
                    return

            # 3. 扩展名过滤
            ext = path.split('.')[-1].strip() if '.' in path and not path.endswith('/') else ''
            if self._cached_extension_mode != u"禁用":
                if ext: # 有扩展名
                    is_match = ext in self._cached_extensions
                    if (self._cached_extension_mode == u"白名单" and not is_match) or \
                       (self._cached_extension_mode == u"黑名单" and is_match):
                        # self.log_message(u"URL被过滤 (扩展名 {} 模式: {}): {}".format(self._cached_extension_mode, ext, url)) # 可选日志
                        return
                elif self._cached_extension_mode == u"白名单": # 白名单模式下，无扩展名的URL被过滤
                    # self.log_message(u"URL被过滤 (扩展名白名单模式，无扩展名): {}".format(url)) # 可选日志
                    return

            # 4. 关键字过滤
            if self._cached_keyword_mode != u"禁用" and self._cached_keywords:
                url_lower = url.lower()
                is_match = any(keyword in url_lower for keyword in self._cached_keywords)
                if (self._cached_keyword_mode == u"黑名单" and is_match) or \
                   (self._cached_keyword_mode == u"白名单" and not is_match):
                    # self.log_message(u"URL被过滤 (关键字 {} 模式): {}".format(self._cached_keyword_mode, url)) # 可选日志
                    return

            # 5. 去重检查 (放在过滤之后，减少不必要的集合操作)
            is_static = ext in self._cached_static_extensions
            unique_key = path if is_static else url # 静态文件按路径去重，其他按完整URL

            if self._cached_unique_only:
                # 使用锁确保线程安全
                with self.lock:
                    if unique_key in self.url_set:
                        return
                    self.url_set.add(unique_key)
            # 如果不去重，或者去重检查通过，继续执行

            # 构建带状态码的URL字符串用于显示
            url_with_status = "{} [{}]".format(url, status_code)

            # 添加到UI（如果需要时间戳，log_message内部会处理）
            self.log_message(u"URL: {}".format(url_with_status)) # 使用log_message统一处理添加和日志

            # 自动保存 (使用缓存的设置)
            if self._cached_save_to_file:
                self.save_url(url_with_status) # 保存带状态码的URL

        except Exception as e:
            # 记录详细错误，包括URL（如果可用）
            error_url = url if 'url' in locals() else "N/A"
            self.log_message(u"处理URL时出错 ({}): {}".format(error_url, str(e)), True)

    def save_url(self, url_to_save): # 参数名修改以更清晰
        # 使用缓存的路径和时间戳设置
        if not self._cached_save_path:
            return
        try:
            save_dir = os.path.dirname(self._cached_save_path)
            # 确保目录存在，仅在需要时创建
            if save_dir and not os.path.exists(save_dir):
                 try:
                     os.makedirs(save_dir)
                 except OSError as dir_e: # 更具体的异常捕获
                     # 如果目录已存在（可能由并发引起），忽略错误
                     if dir_e.errno != 17: # errno 17: File exists
                         self.log_message(u"创建保存目录失败: {} - {}".format(save_dir, str(dir_e)), True)
                         return # 创建目录失败则不继续保存

            # 确保文件路径是绝对路径 (这一步在 load_config 或 browse_file 后应已保证)
            # if not os.path.isabs(self._cached_save_path):
            #     self._cached_save_path = os.path.abspath(self._cached_save_path)

            with self.lock: # 确保文件写入的线程安全
                with open(self._cached_save_path, "a") as f:
                    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._cached_timestamp else ""
                    f.write(timestamp + url_to_save + "\n")
                    f.flush()

        except IOError as io_e: # 捕获IO错误
            error_msg = u"文件写入错误: {} (路径: {})".format(str(io_e), self._cached_save_path)
            self.log_message(error_msg, True)
        except Exception as e: # 捕获其他潜在错误
            error_msg = u"保存URL时发生未知错误: {} (路径: {})".format(str(e), self._cached_save_path)
            self.log_message(error_msg, True)

    def getTabCaption(self):
        return u"URL Extractor Pro"

    def getUiComponent(self):
        return self._main_panel

    def change_theme(self, event):
        new_theme = unicode(self._theme_mode.getSelectedItem())
        if new_theme != self.current_theme:
            self.apply_theme(new_theme)
            self.save_config() # 保存主题设置
            self.log_message(u"主题切换为：{}模式".format(self.current_theme))

    def apply_theme(self, theme_name):
        """应用指定的主题颜色"""
        try:
            theme_colors = self.themes.get(theme_name)
            if not theme_colors:
                self.log_message(u"未找到主题: {}".format(theme_name), True)
                return

            self.current_theme = theme_name

            # 更新组件颜色
            bg = theme_colors["background"]
            fg = theme_colors["foreground"]
            panel_bg = theme_colors["panel"]
            border_color = theme_colors["border"]
            button_bg = theme_colors["button"]

            # --- 更新基础组件 ---
            self._main_panel.setBackground(panel_bg)
            # 使用 self.options_content (已在 _create_options_panel 中赋值)
            if hasattr(self, 'options_content') and self.options_content:
                 self.options_content.setBackground(panel_bg)

            # 输出区域
            self._output.setBackground(bg)
            self._output.setForeground(fg)
            self._log_output.setBackground(bg)
            self._log_output.setForeground(fg)

            # 文本框
            for field in [self._path_field, self._static_ext_field,
                          self._extension_field, self._keyword_field,
                          self._blacklist_field, self._status_codes_field]:
                if field:
                    field.setBackground(bg)
                    field.setForeground(fg)
                    field.setCaretColor(fg) # 设置光标颜色
                    field.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(border_color, 1),
                        BorderFactory.createEmptyBorder(2, 5, 2, 5) # 内边距
                    ))

            # 复选框 (背景通常跟随父面板，主要设置前景)
            for cb in [self._save_to_file, self._unique_only, self._timestamp]:
                 if cb:
                     cb.setBackground(panel_bg) # 设置背景色以防万一
                     cb.setForeground(fg)

            # 下拉框
            for combo in [self._theme_mode, self._export_format,
                          self._extension_mode, self._keyword_mode,
                          self._blacklist_mode, self._status_codes_mode]:
                if combo:
                    # Swing ComboBox 颜色设置比较复杂，有时需要自定义UI或渲染器
                    # 尝试基本设置
                    combo.setBackground(button_bg) # 使用按钮背景色可能效果更好
                    combo.setForeground(fg)
                    # combo.setBorder(...) # 可以尝试设置边框

            # 按钮
            if hasattr(self, 'options_content') and self.options_content:
                 all_buttons = [child for child in self.options_content.getComponents() if isinstance(child, JButton)]
                 for button in all_buttons:
                      button.setBackground(button_bg)
                      button.setForeground(fg)

            # 标签 (主要设置前景)
            # 需要确保 self.extension_panel 等在 _create_filter_panel 中被赋值
            all_labels = []
            panels_with_labels = []
            if hasattr(self, 'options_content'): panels_with_labels.append(self.options_content)
            if hasattr(self, 'extension_panel'): panels_with_labels.append(self.extension_panel)
            if hasattr(self, 'keyword_panel'): panels_with_labels.append(self.keyword_panel)
            if hasattr(self, 'blacklist_panel'): panels_with_labels.append(self.blacklist_panel)
            if hasattr(self, 'status_code_panel'): panels_with_labels.append(self.status_code_panel)

            for panel in panels_with_labels:
                 if panel:
                     all_labels.extend([child for child in panel.getComponents() if isinstance(child, JLabel)])

            for label in all_labels:
               label.setForeground(fg)

            # --- 更新带边框的面板 ---
            border_title_color = fg # 标题用前景色

            def update_titled_border(panel, title):
                 if panel:
                     panel.setBorder(BorderFactory.createCompoundBorder(
                         BorderFactory.createTitledBorder(
                             BorderFactory.createLineBorder(border_color, 1),
                             title,
                             TitledBorder.LEFT,
                             TitledBorder.TOP,
                             self.chinese_font,
                             border_title_color
                         ),
                         BorderFactory.createEmptyBorder(5, 5, 5, 5)
                     ))
                     panel.setBackground(panel_bg) # 设置面板背景

            # 更新过滤器和选项面板的边框和背景 (使用 self.filter_panel, self.options_panel)
            if hasattr(self, 'filter_panel'): update_titled_border(self.filter_panel, u" 过滤规则 ")
            if hasattr(self, 'options_panel'): update_titled_border(self.options_panel, u" 其他选项 ")

            # 更新URL列表和日志面板的边框和背景 (使用 self.url_panel, self.log_panel)
            if hasattr(self, 'url_panel'): update_titled_border(self.url_panel, u" URL列表 ")
            if hasattr(self, 'log_panel'): update_titled_border(self.log_panel, u" 日志信息 ")

            # 更新滚动窗格的边框 (使用 self.url_scroll_pane, self.log_scroll)
            for scroll_pane in [self.url_scroll_pane, self.log_scroll]:
                if scroll_pane:
                    scroll_pane.setBorder(BorderFactory.createLineBorder(border_color))

            # --- 强制重绘 ---
            SwingUtilities.invokeLater(lambda: self._main_panel.revalidate() or self._main_panel.repaint())

        except Exception as e:
            self.log_message(u"应用主题 '{}' 时出错: {}".format(theme_name, str(e)), True)

    def _add_item_listeners(self):
        """在所有相关UI组件创建后统一添加ItemListener"""
        # 为下拉框添加监听器
        for combo in [self._extension_mode, self._keyword_mode,
                      self._blacklist_mode, self._status_codes_mode]:
            if combo:
                combo.addItemListener(self)

        # 为复选框添加监听器
        for checkbox in [self._save_to_file, self._unique_only, self._timestamp]:
            if checkbox:
                checkbox.addItemListener(self)

    def itemStateChanged(self, event):
        """处理复选框和下拉框的状态更改以更新缓存。"""
        # 现在可以安全访问所有组件，因为监听器是在它们都创建后添加的
        source = event.getSource()
        if source in [self._extension_mode, self._keyword_mode, self._blacklist_mode,
                      self._status_codes_mode, self._save_to_file, self._unique_only,
                      self._timestamp]:
            if event.getStateChange() == ItemEvent.SELECTED or event.getStateChange() == ItemEvent.DESELECTED:
                 SwingUtilities.invokeLater(self._update_cached_settings)

    def _update_cached_settings(self):
        try:
            # 更新设置前检查组件是否已初始化 (更健壮的方式)
            if not all(hasattr(self, attr) for attr in [
                '_save_to_file', '_unique_only', '_timestamp',
                '_extension_mode', '_keyword_mode', '_blacklist_mode', '_status_codes_mode',
                '_extension_field', '_keyword_field', '_blacklist_field', '_status_codes_field',
                '_static_ext_field', '_path_field'
            ]):
                 # self.log_message("缓存更新跳过：UI组件尚未完全初始化。") # 可选调试日志
                 return

            # Cache simple boolean/string states directly from UI components
            self._cached_save_to_file = self._save_to_file.isSelected()
            self._cached_unique_only = self._unique_only.isSelected()
            self._cached_timestamp = self._timestamp.isSelected()
            self._cached_extension_mode = self._extension_mode.getSelectedItem()
            self._cached_keyword_mode = self._keyword_mode.getSelectedItem()
            self._cached_blacklist_mode = self._blacklist_mode.getSelectedItem()
            self._cached_status_codes_mode = self._status_codes_mode.getSelectedItem()

            # 从 self.extensions 等实例变量更新缓存（这些变量由 load_config 或 save_all_settings 更新）
            self._cached_extensions = set(self.extensions)
            self._cached_keywords = set(self.keywords)
            self._cached_blacklist = set(self.blacklist)
            self._cached_static_extensions = set(self.static_extensions)

            # 从文本框读取并处理状态码，然后缓存
            self._cached_status_codes = self._get_filtered_set(self._status_codes_field)

            # 从实例变量更新路径缓存
            self._cached_save_path = self.save_path

            # ... (确保保存目录存在) ...
            if self._cached_save_to_file and self._cached_save_path:
                save_dir = os.path.dirname(self._cached_save_path)
                if save_dir and not os.path.exists(save_dir):
                    try:
                        os.makedirs(save_dir)
                        self.log_message(u"自动创建保存目录：{}".format(save_dir))
                    except Exception as dir_e:
                        self.log_message(u"创建保存目录失败：{} - {}".format(save_dir, str(dir_e)), True)

            # self.log_message(u"缓存设置已更新。") # 可选调试日志
        except Exception as e:
            self.log_message(u"更新缓存设置时出错: {}".format(str(e)), True)
