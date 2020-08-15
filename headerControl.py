#!/usr/bin/env python
#coding=utf8
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
import time
import re

# 类BurpExtender（必需），包含用于与Burp套件API交互的所有功能,该插件是header头控制模板


class BurpExtender(IBurpExtender, IHttpListener):

    # 从IBurpExtender接口定义registerExtenderCallbacks
    def registerExtenderCallbacks(self, callbacks):
        # 保留对回调对象的引用（Burp可扩展性特性）
        self._callbacks = callbacks
        # 获取扩展助手对象（Burp可扩展性功能）
        self._helpers = callbacks.getHelpers()
        # 设置将在Extender选项卡中显示的扩展名
        self._callbacks.setExtensionName("headerControl")
        # 将自己注册为HTTP侦听器
        callbacks.registerHttpListener(self)
        
    # 定义过程：从Ihtplistener接口
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # 确定要通过扩展传递的工具：
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32: #如果是repeter/proxy/intruder
            if messageIsRequest:#仅处理请求
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(request) # 这里已经拿到了请求包
                headers = analyzedRequest.getHeaders()#这里拿到了请求包的header头
                # 迭代headers列表，下面除了倒数第二行，其他都是py，和burp没关系
                new_headers = []
                for header in headers:
                    # 查找Content-Type Header
                    if header.startswith("Times:"):
                        t = str(int(round(time.time()*1000)))
                        reg = '\d{13}'
                        result = re.findall(reg,header)
                        header = header.replace(result[0],t)
                        new_headers.append(header)
                    else:
                        new_headers.append(header)
                messageInfo.setRequest(self._helpers.buildHttpMessage(new_headers,request[analyzedRequest.getBodyOffset():]))
                print(new_headers)
