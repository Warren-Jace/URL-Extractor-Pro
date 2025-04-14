# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
import os
from javax.swing import (JPanel, JTextArea, JScrollPane, JButton, JTextField, 
                       JLabel, JCheckBox, JFileChooser, JSplitPane, SwingConstants,
                       JComboBox, JProgressBar, BorderFactory)
from javax.swing.border import TitledBorder
from javax.swing.text import DefaultEditorKit
from java.awt import (BorderLayout, Dimension, FlowLayout, GridBagLayout, 
                     GridBagConstraints, Insets, Font, Color)
from java.util import HashSet
import threading
from datetime import datetime
import re
import json
from urlparse import urlparse
from java.awt.event import ActionListener, ItemListener
from javax.swing import SwingUtilities
from java.awt.event import ItemEvent
import sys

class BurpExtender(IBurpExtender, IHttpListener, ITab, ActionListener, ItemListener):
    def __init__(self):
        # 初始化编码
        reload(sys)
        sys.setdefaultencoding('utf-8')

        # 初始化缓存和配置
        self._cache_lock = threading.Lock()
        self._url_cache = {}  # 用于缓存URL处理结果
        self._last_processed_time = 0  # 最后处理时间
        self._processing_interval = 0.5  # 处理间隔时间（秒）

        # 配置项初始化
        self._max_url_length = 1024  # URL最大长度
        self._max_cache_size = 1000  # 最大缓存数量
        self._max_processing_threads = 10  # 最大处理线程数

        # 初始化默认保存路径和其他设置
        self.save_path = os.path.expanduser("~/Desktop/urls.txt")
        self.blacklist = set(["example.com", "test.com"])
        self.extensions = set(["js", "css", "jpg", "png", "html"])
        self.keywords = set(["jquery", "bootstrap", "angular"])
        self.url_set = set()
        self.config_file = os.path.expanduser("~/.burp_url_extractor_config.json")

        # 默认静态文件后缀
        self.static_extensions = {"js", "css", "png", "jpg", "gif", "exe", "ttf", "jpeg"}

        # 缓存设置以提高性能
        self._cached_save_path = self.save_path
        self._cached_blacklist = set()
        self._cached_blacklist_mode = u"黑名单"  # 默认模式
        self._cached_extensions = set()
        self._cached_extension_mode = u"禁用"  # 默认模式
        self._cached_keywords = set()
        self._cached_keyword_mode = u"禁用"  # 默认模式
        self._cached_status_codes = set()
        self._cached_status_codes_mode = u"禁用"  # 默认模式
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
        self.current_theme = u"明亮"
        self.themes = {
            u"明亮": {
                "background": Color(252, 252, 252),
                "foreground": Color(50, 50, 50),
                "panel": Color(250, 250, 250),
                "border": Color(200, 200, 200),
                "button": Color(240, 240, 240)
            },
            u"暗黑": {
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

        # 初始化UI
        self._initUI()

        # 加载配置
        self.load_config()

        # 更新缓存设置
        self._update_cached_settings()

        # 注册HTTP监听器
        callbacks.registerHttpListener(self)
        # 添加插件到Burp的UI
        callbacks.addSuiteTab(self)
        self.log_message(u"插件初始化成功")
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


    def save_config(self):
        try:
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)

            config = {
                'save_path': self.save_path,
                'blacklist': list(self.blacklist),
                'extensions': list(self.extensions),
                'keywords': list(self.keywords),
                'static_extensions': list(self.static_extensions),
                'theme': self.current_theme,  # 保存当前主题
                'status_codes': list(self._cached_status_codes),  # 保存过滤状态码
                'status_codes_mode': self._cached_status_codes_mode  # 保存状态码模式
            }

            temp_file = self.config_file + '.tmp'
            with open(temp_file, 'wb') as f:
                json_str = json.dumps(config, ensure_ascii=False, indent=2)
                f.write(json_str.encode('utf-8'))
                f.flush()
                os.fsync(f.fileno())

            if os.path.exists(self.config_file):
                os.remove(self.config_file)
            os.rename(temp_file, self.config_file)

        except Exception as e:
            self._callbacks.printError("Failed to save config: {}".format(str(e)))

    def _load_config_values(self, config):
        self.save_path = config.get('save_path', self.save_path)
        self.blacklist = set(config.get('blacklist', list(self.blacklist)))
        self.extensions = set(config.get('extensions', list(self.extensions)))
        self.keywords = set(config.get('keywords', list(self.keywords)))
        self.static_extensions = set(config.get('static_extensions', list(self.static_extensions)))
        self.current_theme = config.get('theme', self.current_theme)
        self._cached_status_codes = set(config.get('status_codes', list(self._cached_status_codes)))
        self._cached_status_codes_mode = config.get('status_codes_mode', self._cached_status_codes_mode)


    def _initUI(self):
        """初始化UI组件"""
        self._main_panel = JPanel(BorderLayout(0, 0))

        # 创建并添加控制面板
        control_panel = self._create_control_panel()

        # 创建并添加输出面板
        output_panel = self._create_output_panel()

        # 主分割面板
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, True, control_panel, output_panel)
        main_split_pane.setBorder(None)
        main_split_pane.setDividerLocation(150)
        main_split_pane.setResizeWeight(0.3)

        self._main_panel.add(main_split_pane, BorderLayout.CENTER)

        # 添加 ItemListener
        self._add_item_listeners()

        # 应用当前主题
        self.apply_theme(self.current_theme)

        # self.statistics_label = JLabel("提取的 URL 总数: 10 | 过滤掉的 URL 数量: 0")
        # self.statistics_label.setFont(self.chinese_font)  # 使用中文字体
        # self._main_panel.add(self.statistics_label, BorderLayout.SOUTH)

        self.progress_bar = JProgressBar(0, 100)
        self._main_panel.add(self.progress_bar, BorderLayout.NORTH)

        # 确保_log_output已创建
        if not self._log_output:
            self._log_output = JTextArea()

    # 处理HTTP消息
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """处理HTTP消息"""
        if messageIsRequest:
            # 使用线程处理URL
            thread = threading.Thread(target=self._process_url, args=(toolFlag, messageIsRequest, messageInfo))
            thread.start()
            return

        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl().toString()
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            status_code = str(response_info.getStatusCode())

            # URL长度检查
            if len(url) > self._max_url_length:
                self.log_message(u"URL过长被跳过：{}...".format(url[:100]), True)
                return

            # 缓存检查
            with self._cache_lock:
                if url in self._url_cache:
                    return
                self._url_cache[url] = True
                if len(self._url_cache) > self._max_cache_size:
                    self._url_cache.popitem(last=False)

            # 增强路径提取
            self._extract_and_process_paths(url, messageInfo)

            # 过滤逻辑
            if not self._should_process_url(url, status_code):
                return

            # 构建带状态码的URL字符串
            url_with_status = "{} [{}]".format(url, status_code)
            self._add_url_to_ui(url_with_status)

            # 自动保存
            if self._cached_save_to_file:
                self.save_url(url_with_status)

        except Exception as e:
            self.log_message(u"处理URL时出错：{}".format(str(e)), True)


    def _process_url(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                return

            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl().toString()

            if len(url) > self._max_url_length:
                self.log_message(u"URL过长被跳过：{}...".format(url[:100]), True)
                return

            with self._cache_lock:
                if url in self._url_cache:
                    return
                self._url_cache[url] = True
                if len(self._url_cache) > self._max_cache_size:
                    self._url_cache.popitem(last=False)

            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            status_code = str(response_info.getStatusCode())

            self._extract_and_process_paths(url, messageInfo)

            if not self._should_process_url(url, status_code):
                return

            url_with_status = "{} [{}]".format(url, status_code)
            self._add_url_to_ui(url_with_status)

            if self._cached_save_to_file:
                self.save_url(url_with_status)

        except Exception as e:
            self.log_message(u"处理URL时出错：{}".format(str(e)), True)

    # 提取和处理路径
    def _extract_and_process_paths(self, url, messageInfo):
        """增强路径提取功能"""
        try:
            response = messageInfo.getResponse()
            response_info = self._helpers.analyzeResponse(response)
            response_body = self._helpers.bytesToString(response[response_info.getBodyOffset():])

            # 路径匹配模式
            path_patterns = [
                r'\"(/[^\"\\s?#]+)\"',       # 常规路径
                r'url\\([\"\']?(/[^\"\'\\s)]+)', # CSS中的路径
                r'href=[\"\']?(/[^\"\'>]+)',  # HTML中的路径
                r'src=[\"\']?(/[^\"\'>]+)',  # 资源引用路径
                r'/[^\"\\s\'<>()]+\\.(?:js|css|png|jpg|gif|svg)'  # 常见资源文件
            ]

            # 解析基础URL信息
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            base_scheme = parsed_url.scheme

            # 收集并去重路径
            unique_paths = set()
            for pattern in path_patterns:
                matches = re.findall(pattern, response_body)
                unique_paths.update(m for m in matches if len(m) < 256)  # 限制路径长度

            # 拼接并记录有效URL
            for path in sorted(unique_paths):
                if not path.startswith('/'):
                    continue
                try:
                    combined_url = "{}://{}{}".format(base_scheme, base_domain, path)
                    self.log_message(u"发现路径: {}".format(combined_url))
                    self._add_url_to_ui(combined_url)
                except Exception as e:
                    self.log_message(u"URL拼接错误: {}".format(str(e)), True)
        except Exception as e:
            self.log_message(u"路径提取错误: {}".format(str(e)), True)


    def _should_process_url(self, url, status_code):
        """根据过滤规则决定是否处理URL"""
        if self._cached_status_codes_mode != u"禁用":
            is_match = status_code in self._cached_status_codes
            if (self._cached_status_codes_mode == u"白名单" and not is_match) or \
               (self._cached_status_codes_mode == u"黑名单" and is_match):
                return False

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if self._cached_blacklist_mode != u"禁用" and self._cached_blacklist and domain:
            is_match = any(blacklisted in domain for blacklisted in self._cached_blacklist)
            if (self._cached_blacklist_mode == u"黑名单" and is_match) or \
               (self._cached_blacklist_mode == u"白名单" and not is_match):
                return False

        path = parsed_url.path.lower()
        ext = path.split('.')[-1].strip() if '.' in path and not path.endswith('/') else ''
        if self._cached_extension_mode != u"禁用":
            if ext:
                is_match = ext in self._cached_extensions
                if (self._cached_extension_mode == u"白名单" and not is_match) or \
                   (self._cached_extension_mode == u"黑名单" and is_match):
                    return False
            elif self._cached_extension_mode == u"白名单":
                return False

        if self._cached_keyword_mode != u"禁用" and self._cached_keywords:
            url_lower = url.lower()
            is_match = any(keyword in url_lower for keyword in self._cached_keywords)
            if (self._cached_keyword_mode == u"黑名单" and is_match) or \
               (self._cached_keyword_mode == u"白名单" and not is_match):
                return False

        return True


    # 添加URL到UI
    def _add_url_to_ui(self, url_with_status):
        """将URL添加到UI"""
        if not self._output.getText().strip():
            self._output.setText(url_with_status)
        else:
            self._output.append("\n" + url_with_status)
        # 滚动到最新位置
        self._output.setCaretPosition(self._output.getDocument().getLength())
 
    def save_url(self, url_to_save):
        """保存URL到指定文件"""
        if not self._cached_save_path:
            return
        try:
            save_dir = os.path.dirname(self._cached_save_path)
            if save_dir and not os.path.exists(save_dir):
                try:
                    os.makedirs(save_dir)
                except OSError as dir_e:
                    if dir_e.errno != 17:
                        self.log_message(u"创建保存目录失败: {} - {}".format(save_dir, str(dir_e)), True)
                        return

            with self.lock:
                with open(self._cached_save_path, "a") as f:
                    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._cached_timestamp else ""
                    f.write(timestamp + url_to_save + "\n")
                    f.flush()

        except IOError as io_e:
            error_msg = u"文件写入错误: {} (路径: {})".format(str(io_e), self._cached_save_path)
            self.log_message(error_msg, True)
        except Exception as e:
            error_msg = u"保存URL时发生未知错误: {} (路径: {})".format(str(e), self._cached_save_path)
            self.log_message(error_msg, True)

    def _add_item_listeners(self):
        """在所有相关UI组件创建后统一添加ItemListener"""
        for combo in [self._extension_mode, self._keyword_mode,
                      self._blacklist_mode, self._status_codes_mode]:
            if combo:
                combo.addItemListener(self)

        for checkbox in [self._save_to_file, self._unique_only, self._timestamp]:
            if checkbox:
                checkbox.addItemListener(self)



    def itemStateChanged(self, event):
        """处理复选框和下拉框的状态更改以更新缓存。"""
        source = event.getSource()
        if source in [self._extension_mode, self._keyword_mode, self._blacklist_mode,
                      self._status_codes_mode, self._save_to_file, self._unique_only,
                      self._timestamp]:
            if event.getStateChange() == ItemEvent.SELECTED or event.getStateChange() == ItemEvent.DESELECTED:
                SwingUtilities.invokeLater(self._update_cached_settings)


    def _update_cached_settings(self):
        try:
            if not all(hasattr(self, attr) for attr in [
                '_save_to_file', '_unique_only', '_timestamp',
                '_extension_mode', '_keyword_mode', '_blacklist_mode', '_status_codes_mode',
                '_extension_field', '_keyword_field', '_blacklist_field', '_status_codes_field',
                '_static_ext_field', '_path_field'
            ]):
                return

            self._cached_save_to_file = self._save_to_file.isSelected()
            self._cached_unique_only = self._unique_only.isSelected()
            self._cached_timestamp = self._timestamp.isSelected()
            self._cached_extension_mode = self._extension_mode.getSelectedItem()
            self._cached_keyword_mode = self._keyword_mode.getSelectedItem()
            self._cached_blacklist_mode = self._blacklist_mode.getSelectedItem()
            self._cached_status_codes_mode = self._status_codes_mode.getSelectedItem()

            self._cached_extensions = set(self.extensions)
            self._cached_keywords = set(self.keywords)
            self._cached_blacklist = set(self.blacklist)
            self._cached_static_extensions = set(self.static_extensions)

            self._cached_status_codes = self._get_filtered_set(self._status_codes_field)

            self._cached_save_path = self.save_path

            if self._cached_save_to_file and self._cached_save_path:
                save_dir = os.path.dirname(self._cached_save_path)
                if save_dir and not os.path.exists(save_dir):
                    try:
                        os.makedirs(save_dir)
                        self.log_message(u"自动创建保存目录：{}".format(save_dir))
                    except Exception as dir_e:
                        self.log_message(u"创建保存目录失败：{} - {}".format(save_dir, str(dir_e)), True)

        except Exception as e:
            self.log_message(u"更新缓存设置时出错: {}".format(str(e)), True)




    

    def _update_log_output(self, log_line):
        if self._log_output.getText().strip():
            self._log_output.append("\n")
        self._log_output.append(log_line + "\n")
        self._log_output.setCaretPosition(self._log_output.getDocument().getLength())

    def getTabCaption(self):
        return u"URL Extractor Pro"



    def getUiComponent(self):
        return self._main_panel

    # 更改主题
    def change_theme(self, event):
        """更改主题"""
        new_theme = unicode(self._theme_mode.getSelectedItem())
        if new_theme != self.current_theme:
            self.apply_theme(new_theme)
            self.save_config()
            self.log_message(u"主题切换为：{}模式".format(self.current_theme))


    def _create_control_panel(self):
        control_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridwidth = GridBagConstraints.REMAINDER
        gbc.weightx = 1.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 0, 0)

        gbc.gridy = 0
        self.filter_panel = self._create_filter_panel()
        control_panel.add(self.filter_panel, gbc)

        gbc.gridy = 1
        self.options_panel = self._create_options_panel()
        control_panel.add(self.options_panel, gbc)

        return control_panel

    def _create_filter_panel(self):
        filter_panel = JPanel(GridBagLayout())
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

        extension_panel, self._extension_field, self._extension_mode = create_filter_option(
            u"扩展名", ",".join(self.extensions), u"输入要过滤的扩展名，用逗号分隔")
        keyword_panel, self._keyword_field, self._keyword_mode = create_filter_option(
            u"关键字", ",".join(self.keywords), u"输入要过滤的关键字，用逗号分隔")
        blacklist_panel, self._blacklist_field, self._blacklist_mode = create_filter_option(
            u"域名", ", ".join(self.blacklist), u"输入要过滤的域名，用逗号分隔")
        status_code_panel, self._status_codes_field, self._status_codes_mode = create_filter_option(
            u"状态码", "200,301,302", u"输入要过滤的状态码，用逗号分隔")

        filter_gbc = GridBagConstraints()
        filter_gbc.fill = GridBagConstraints.HORIZONTAL
        filter_gbc.insets = Insets(5, 5, 5, 10)
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
        filter_gbc.insets = Insets(5, 5, 5, 5)
        filter_panel.add(status_code_panel, filter_gbc)

        return filter_panel

    def _create_options_panel(self):
        options_panel = JPanel(BorderLayout())
        options_panel.setBorder(self._create_titled_border(u" 其他选项 "))

        self.options_content = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        path_label = self._create_label(u"保存路径", 65)
        self.options_content.add(path_label)
        self._path_field = JTextField(self.save_path, 30)
        self._path_field.setFont(self.chinese_font)
        self._path_field.setEditable(True)
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
        self._theme_mode.addActionListener(self.change_theme)
        self.options_content.add(self._theme_mode)

        self._save_to_file = self._create_checkbox(u"自动保存", True, u"自动保存URL到文件")
        self._unique_only = self._create_checkbox(u"去重", True, u"URL去重(静态文件按路径)")
        self._timestamp = self._create_checkbox(u"时间戳", False, u"日志和保存时添加时间戳")
        self.options_content.add(self._save_to_file)
        self.options_content.add(self._unique_only)
        self.options_content.add(self._timestamp)

        format_label = self._create_label(u"导出格式", 65)
        self.options_content.add(format_label)
        self._export_format = JComboBox([u"TXT", u"JSON", u"CSV"])
        self._export_format.setFont(self.chinese_font)
        self._export_format.setPreferredSize(Dimension(80, 28))
        self.options_content.add(self._export_format)

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
        output_panel = JPanel(BorderLayout(0, 0))

        url_panel = JPanel(BorderLayout(0, 0))
        url_panel.setBorder(self._create_titled_border(u" URL列表 "))
        self._output = JTextArea()
        self._output.setFont(Font("Consolas", Font.PLAIN, 12))
        self._output.setEditable(False)
        self._output.setLineWrap(False)
        url_scroll_pane = JScrollPane(self._output,
                                      JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                      JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        url_scroll_pane.getVerticalScrollBar().setUnitIncrement(16)
        url_panel.add(url_scroll_pane, BorderLayout.CENTER)
        self.url_panel = url_panel
        self.url_scroll_pane = url_scroll_pane

        log_panel = JPanel(BorderLayout(0, 0))
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
        self.log_panel = log_panel
        self.log_scroll = log_scroll

        split_pane_vertical = JSplitPane(JSplitPane.VERTICAL_SPLIT, True, url_panel, log_panel)
        split_pane_vertical.setBorder(None)
        split_pane_vertical.setDividerLocation(600)
        split_pane_vertical.setResizeWeight(0.7)
        output_panel.add(split_pane_vertical, BorderLayout.CENTER)

        return output_panel

    def _create_label(self, text, width):
        label = JLabel(text, SwingConstants.RIGHT)
        label.setFont(self.chinese_font)
        label.setPreferredSize(Dimension(width, 28))
        return label

    def _create_button(self, text, action_listener, width):
        btn = JButton(text)
        btn.setFont(self.chinese_font)
        btn.addActionListener(action_listener)
        btn.setPreferredSize(Dimension(width, 28))
        return btn

    def _create_checkbox(self, text, selected, tooltip):
        cb = JCheckBox(text, selected)
        cb.setFont(self.chinese_font)
        cb.setToolTipText(tooltip)
        return cb

    def _create_titled_border(self, title):
        return BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY),
                title,
                TitledBorder.LEFT,
                TitledBorder.TOP,
                self.chinese_font,
                Color.DARK_GRAY
            ),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        )

    def export_urls(self, event):
        """导出URL到文件"""
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
            else:
                with open(self.save_path, "w") as f:
                    f.write("\n".join(urls))

            self.log_message(u"URL导出成功，格式为：{}，路径为：{}".format(export_format, self.save_path))
        except Exception as e:
            self.log_message(u"导出错误：{}".format(str(e)), True)


    def browse_file(self, event):
        """浏览文件以选择保存路径"""
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            self.save_path = chooser.getSelectedFile().getAbsolutePath()
            self._path_field.setText(self.save_path)
            self.save_config()


    def clear_output(self, event):
        """清空URL输出"""
        self._output.setText("")
        self.url_set.clear()
        self.log_message(u"URL输出清空")

    def clear_log(self, event):
        """清空日志输出"""
        self._log_output.setText("")
        self.log_message(u"日志清空")

    def save_all_settings(self, event):
        """保存所有配置设置"""
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
        try:
            self.log_message(u"设置保存成功：")
            self.log_message(u"- 保存路径：{}".format(self.save_path))
            
            # 扩展名及模式
            extension_mode = self._extension_mode.getSelectedItem() if hasattr(self, '_extension_mode') else u"禁用"
            self.log_message(u"- 扩展名：{} ({} 模式)".format(
                ", ".join(sorted(self.extensions)) if self.extensions else u"无",
                extension_mode
            ))
            
            # 关键字及模式
            keyword_mode = self._keyword_mode.getSelectedItem() if hasattr(self, '_keyword_mode') else u"禁用"
            self.log_message(u"- 关键字：{} ({} 模式)".format(
                ", ".join(sorted(self.keywords)) if self.keywords else u"无",
                keyword_mode
            ))
            
            # 域名及模式
            blacklist_mode = self._cached_blacklist_mode if hasattr(self, '_cached_blacklist_mode') else u"禁用"
            self.log_message(u"- 域名：{} ({} 模式)".format(
                ", ".join(sorted(self.blacklist)) if self.blacklist else u"无",
                blacklist_mode
            ))
            
            # 静态后缀
            self.log_message(u"- 静态后缀：{}".format(
                ", ".join(sorted(self.static_extensions)) if self.static_extensions else u"无"
            ))
            
            # 当前主题
            self.log_message(u"- 当前主题：{}".format(self.current_theme))
            
            # 过滤状态码及模式
            status_codes_mode = self._cached_status_codes_mode if hasattr(self, '_cached_status_codes_mode') else u"禁用"
            self.log_message(u"- 状态码：{} ({} 模式)".format(
                ", ".join(sorted(self._cached_status_codes)) if self._cached_status_codes else u"无",
                status_codes_mode
            ))
        except Exception as e:
            self.log_message(u"日志记录错误：{}".format(str(e)), True)

    def save_config(self):
        """保存当前配置到文件"""
        try:
            config = {
                "save_path": self.save_path,
                "blacklist": list(self.blacklist),
                "extensions": list(self.extensions),
                "keywords": list(self.keywords),
                "static_extensions": list(self.static_extensions),
                "theme": self.current_theme
            }
            with open("config.json", "w") as config_file:
                json.dump(config, config_file, indent=2)
            self.log_message(u"配置保存成功")
        except Exception as e:
            self.log_message(u"保存配置时出错：{}".format(str(e)), True)

    def load_config(self):
        """从文件加载配置"""
        try:
            with open("config.json", "r") as config_file:
                config = json.load(config_file)
            self.save_path = config.get("save_path", "")
            self.blacklist = set(config.get("blacklist", []))
            self.extensions = set(config.get("extensions", []))
            self.keywords = set(config.get("keywords", []))
            self.static_extensions = set(config.get("static_extensions", []))
            self.current_theme = config.get("theme", "明亮")
            self.apply_theme(self.current_theme)
            self.log_message(u"配置加载成功")
        except FileNotFoundError:
            self.log_message(u"未找到配置文件，使用默认设置")
        except Exception as e:
            self.log_message(u"加载配置时出错：{}".format(str(e)), True)

    def init_ui(self):
        """初始化UI组件"""
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        control_panel = self._create_control_panel()
        output_panel = self._create_output_panel()

        self._main_panel.add(control_panel, BorderLayout.NORTH)
        self._main_panel.add(output_panel, BorderLayout.CENTER)

        self.load_config()
        self._add_item_listeners()
        self._update_cached_settings()

    # 应用主题
    def apply_theme(self, theme_name):
        """应用指定的主题颜色"""
        try:
            theme_colors = self.themes.get(theme_name)
            if not theme_colors:
                self.log_message(u"未找到主题: {}".format(theme_name), True)
                return

            self.current_theme = theme_name

            # 检查组件是否初始化
            if not self._main_panel or not self._output or not self._log_output:
                self.log_message(u"组件未初始化，跳过应用主题", True)
                return

            # 更新组件颜色
            bg = theme_colors["background"]
            fg = theme_colors["foreground"]
            panel_bg = theme_colors["panel"]
            border_color = theme_colors["border"]
            button_bg = theme_colors["button"]

            # 更新基础组件
            self._main_panel.setBackground(panel_bg)
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
                    field.setCaretColor(fg)
                    field.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(border_color, 1),
                        BorderFactory.createEmptyBorder(2, 5, 2, 5)
                    ))

            # 复选框
            for cb in [self._save_to_file, self._unique_only, self._timestamp]:
                if cb:
                    cb.setBackground(panel_bg)
                    cb.setForeground(fg)

            # 下拉框
            for combo in [self._theme_mode, self._export_format,
                          self._extension_mode, self._keyword_mode,
                          self._blacklist_mode, self._status_codes_mode]:
                if combo:
                    combo.setBackground(button_bg)
                    combo.setForeground(fg)

            # 按钮
            if hasattr(self, 'options_content') and self.options_content:
                all_buttons = [child for child in self.options_content.getComponents() if isinstance(child, JButton)]
                for button in all_buttons:
                    button.setBackground(button_bg)
                    button.setForeground(fg)

            # 标签
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

            # 更新带边框的面板
            border_title_color = fg

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
                    panel.setBackground(panel_bg)

            # 更新过滤器和选项面板的边框和背景
            if hasattr(self, 'filter_panel'): update_titled_border(self.filter_panel, u" 过滤规则 ")
            if hasattr(self, 'options_panel'): update_titled_border(self.options_panel, u" 其他选项 ")

            # 更新URL列表和日志面板的边框和背景
            if hasattr(self, 'url_panel'): update_titled_border(self.url_panel, u" URL列表 ")
            if hasattr(self, 'log_panel'): update_titled_border(self.log_panel, u" 日志信息 ")

            # 更新滚动窗格的边框
            for scroll_pane in [self.url_scroll_pane, self.log_scroll]:
                if scroll_pane:
                    scroll_pane.setBorder(BorderFactory.createLineBorder(border_color))

            # 强制重绘
            SwingUtilities.invokeLater(lambda: self._main_panel.revalidate() or self._main_panel.repaint())

        except Exception as e:
            self.log_message(u"应用主题 '{}' 时出错: {}".format(theme_name, str(e)), True)

    def log_message(self, message, is_error=False):
            try:
                timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
                log_line = timestamp + message  # 不需要编码为字节

                # 检查组件是否初始化
                if not self._log_output:
                    self._callbacks.printError("日志输出组件未初始化")
                    return

                if is_error:
                    self._callbacks.printError(log_line)
                else:
                    self._callbacks.printOutput(log_line)

                # 提取URL并显示到URL面板
                if message.startswith(u"URL:"):
                    match = re.match(r"URL: (.*?)(?:\\s+\\[Status: (\\d+)\\])?$", message)
                    if match:
                        url = match.group(1).strip()
                        status = match.group(2)
                        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") if self._cached_timestamp else ""
                        if status:
                            status_color = Color.GREEN if status == "200" else Color.ORANGE if status.startswith("3") else Color.RED
                            status_html = "<font color='#%02x%02x%02x'>[%s]</font>" % (
                                status_color.getRed(), status_color.getGreen(), status_color.getBlue(), status
                            )
                            url_output = timestamp + url + " " + status_html
                        else:
                            url_output = timestamp + url

                        with self.lock:
                            current_text = self._output.getText()
                            if current_text:
                                if not current_text.endswith("\n\n"):
                                    self._output.append("\n")
                                self._output.append(url_output + "\n")
                            else:
                                self._output.setText(url_output + "\n")

                        SwingUtilities.invokeLater(lambda: self._output.setCaretPosition(self._output.getDocument().getLength()))

                message_lines = message.split("\n")
                for line in message_lines:
                    if line.strip():
                        if self._log_output.getText().strip():
                            self._log_output.append("\n")
                        log_line = timestamp + line.strip() + "\n"
                        self._log_output.append(log_line)

                self._log_output.setCaretPosition(self._log_output.getDocument().getLength())

                if is_error:
                    self._callbacks.printError(message)  # 使用原始消息
                else:
                    self._callbacks.printOutput(message)  # 使用原始消息

            except Exception as e:
                self._callbacks.printError(u"日志记录错误：{}".format(str(e)))


class MockCallbacks:
    def getHelpers(self):
        # 返回一个模拟的helpers对象
        return None
    def setExtensionName(self, name):
        print("Extension name set to: {}".format(name))
        print("")

    def registerHttpListener(self, listener):
        print("HTTP Listener registered.")
        print("")

    def addSuiteTab(self, tab):
        print("Suite tab added.")
        print("")

    def printOutput(self, message):
        print("Output: {}".format(message))
        print("")

    def printError(self, message):
        print("Error: {}".format(message))
        print("")

# 创建并注册插件实例
try:
    extender = BurpExtender()
    mock_callbacks = MockCallbacks()
    extender.registerExtenderCallbacks(mock_callbacks)
    extender._initUI()  # 确保UI在注册回调后初始化

except Exception as e:
    print("插件注册失败: {}".format(str(e)))
