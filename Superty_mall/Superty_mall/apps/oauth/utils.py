from itsdangerous import Serializer
from django.conf import settings


def check_access_token(access_token_openid):
    """
    反解 反序列化access_token_openid
    :param access_token_openid: openid密文
    :return: openid=明文
    """
    # 创建序列化器对象： 序列化和反序列化的对象的参数必须时一模一样的
    s = Serializer(settings.SECRET_KEY, 600)

    # 反序列化openid密文
    try:
        data = s.load(access_token_openid)
    except BadData: # openid密文过期
        return None
    else:
        # 返回openid明文
        return data.get('openid')


def generate_access_token(openid):
    """
    签名 序列化openid
    :param openid: openid明文
    :return: token(openid密文)
    """
    # 创建序列化器对象
    # s = Serializer('密钥：越复杂越安全', '过期时间')
    s = Serializer(settings.SECRET_KEY, 600)

    # 准备待序列化的字典数据
    data = {'openid': openid}

    # 调用dumps方法进行序列化
    token = s.dumps(data)

    # 返回序列化后的数据
    return token.decode()