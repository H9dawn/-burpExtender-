#!/usr/bin/env python
#coding=utf8
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
import time
import re
# 类BurpExtender（必需），包含用于与Burp套件API交互的所有功能,该插件是针对请求字段的模板


class BurpExtender(IBurpExtender, IHttpListener):
    # 从IBurpExtender接口定义registerExtenderCallbacks
    def registerExtenderCallbacks(self, callbacks):
        # 保留对回调对象的引用（Burp可扩展性特性）
        self._callbacks = callbacks
        # 获取扩展助手对象（Burp可扩展性功能） 
        self._helpers = callbacks.getHelpers()
        # 设置将在Extender选项卡中显示的扩展名
        self._callbacks.setExtensionName("paramControl")
        # 将自己注册为HTTP侦听器
        callbacks.registerHttpListener(self)
        
    # 定义过程：从Ihtplistener接口
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 确定要通过扩展传递的工具：
        if toolFlag == 64 or toolFlag == 16: #如果是repeter/proxy
            if messageIsRequest:#仅处理请求 
                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(request) 
                param = analyzedRequest.getParameters()#获取参数列表，参数分为三种类型，URL中的参数，cookie中的参数，body中的参数，因为匹配规则有些不同？
                for p in param:
                    key= p.getName() #获取参数名
                    if key.startswith("a"):
                        #value = p.getValue() #获取参数值
                        value = '999'
                        print(key+'='+value)
                        newParam = self._helpers.buildParameter(key, value, p.getType());
                        self._helpers.removeParameter(request,p)
                        self._helpers.addParameter(request,newParam)
                messageInfo.setRequest(self._helpers.updateParameter(request, newParam))#构造新的请求包