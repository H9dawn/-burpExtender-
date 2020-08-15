# -*- coding:utf-8 -*-

import re

from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory

from java.io import PrintWriter

'''
这个脚本算是修改返回包的模板
尚未解决：burp自带的接口，好像没有改部分数据包颜色的，只能用这种特征，在关键词前后添加*号
假如以后想把敏感参数，比如callback这种参数进行标记，就很难搞了，不能在周围添加特征。
'''

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("sensInfoScan")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
            if messageIsRequest:
                return
            response = messageInfo.getResponse()
            analyzedResponse = self._helpers.analyzeResponse(response)
            headers = analyzedResponse.getHeaders()
            message = response[analyzedResponse.getBodyOffset():].tostring()
            phoneRes = isPhone(message)
            idCardRes = isIdCard(message)
            emailRes = isEmail(message)
            if phoneRes or idCardRes or emailRes:#有就变色
                messageInfo.setHighlight('yellow')
                message = changeMessage('phone',phoneRes,message)#判断并替换返回包内容的函数
                message = changeMessage('idCard',idCardRes,message)
                message = changeMessage('email',emailRes,message)
                print("******************************************************************")
                print("")
                new_body = self._helpers.stringToBytes(message)
                messageInfo.setResponse(self._helpers.buildHttpMessage(headers, new_body))

def isPhone(string):
    iphones = re.findall(r'((13[0-9]|14[5-9]|15[012356789]|166|17[0-8]|18[0-9]|19[8-9])[0-9]{8})', string)#匹配13x,14x有限制的。
    res = []
    if iphones != []:
        for i in iphones:
            lens = string.find(i[0])#找第一个手机号第一位
            if (string[lens-1:lens].isdigit()) or (string[lens+11:lens+12].isdigit()):#isdigit表示判断是否只由数字组成,这一行判断是为了判断（超过11位的纯数字可能就不是手机号）
                pass
            else:
                res.append(i[0])
        if res != []:
            return res
        else:
            return False
    else:
        return False

def isIdCard(string):#自己写的垃圾正则，网上其他简化的实在是太不行了，只匹配18位的
    idcards = re.findall(r'([1-6]{1}[0-9]{1}\d{4}19\d{2}[0-1]{1}\d{1}[0-3]{1}[0-9]{1}\d{3}[0-9Xx]{1})', string)
    if idcards != []:
        return idcards
    return False

def isEmail(string):#邮箱有误报，csdn存在这样的东西 我是没想到的 chizhiyiheng@240.png 难道还要整个字典？好麻烦啊
    emails = re.findall(r'[a-z0-9A-Z_]{1,19}@[0-9a-zA-Z]{1,13}\.[a-z]{1,6}', string)
    if emails != []:
        return emails
    else:
        return False
        
def changeMessage(flag,Res,message):
    if (Res!=False):
        for i in Res:
            print(flag + " : " + str(i))
            j = '*********' + str(i) + '*********'
            message = message.replace(str(i),j)
    return message


