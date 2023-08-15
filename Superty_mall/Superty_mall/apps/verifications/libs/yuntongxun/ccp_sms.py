# -*- coding:utf-8 -*-

# import ssl
# ssl._create_default_https_context =ssl._create_stdlib_context # 解决Mac开发环境下，网络错误的问题
from Superty_mall.apps.verifications.libs.yuntongxun.CCPRestSDK import REST

# 说明：主账号，登陆云通讯网站后，可在"控制台-应用"中看到开发者主账号ACCOUNT SID
_accountSid = '8aaf070881368efb01815cf8686a0b7d'

# 说明：主账号Token，登陆云通讯网站后，可在控制台-应用中看到开发者主账号AUTH TOKEN
_accountToken = 'b447ea736f5d489695375611798505ab'

# 请使用管理控制台首页的APPID或自己创建应用的APPID
_appId = '2c94811c87c2d4870187ef0102d4093b'

# 说明：请求地址，生产环境配置成app.cloopen.com
_serverIP = 'app.cloopen.com'

# 说明：请求端口 ，生产环境为8883
_serverPort = "8883"

# 说明：REST API版本号保持不变
_softVersion = '2013-12-26'

# 云通讯官方提供的发送短信代码实例
# 发送模板短信
# @param to 手机号码
# @param datas 内容数据 格式为数组 例如：{'12','34'}，如不需替换请填 ''
# @param $tempId 模板Id
# def sendTemplateSMS(to, datas, tempId):
#     # 初始化REST SDK
#
#     rest = REST(_serverIP, _serverPort, _softVersion)
#     rest.setAccount(_accountSid, _accountToken)
#     rest.setAppId(_appId)
#
#     result = rest.sendTemplateSMS(to, datas, tempId)
#     print(result)

class CCP(object):
    """发送短信验证码的单例类"""

    def __new__(cls, *args, **kwargs):
        """
        定义单例的初始化方法
        :return: 单例
        """

        # 判断单例是否存在：_instance属性中存储的就是单例
        if not hasattr(cls, '_instance'):
            # 如果单例不存在，初始化单例
            cls._instance = super(CCP, cls).__new__(cls, *args, **kwargs)
            cls._instance.rest = REST(_serverIP, _serverPort, _softVersion)
            cls._instance.rest.setAccount(_accountSid, _accountToken)
            cls._instance.rest.setAppId(_appId)

        # 返回单例
        return cls._instance

    def sendTemplateSMS(self, to, datas, tempId):
        result = self.rest.sendTemplateSMS(to, datas, tempId)
        print(result)
        if result.get('statusCode') == '000000':
            return 0
        else:
            return -1





if __name__ == '__main__':
    # 注意： 测试的短信模板编号为1
    CCP().sendTemplateSMS('18702633001', ['1888', 5], 1)
