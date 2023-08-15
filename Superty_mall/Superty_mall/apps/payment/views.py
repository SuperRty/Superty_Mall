from django.shortcuts import render
from django import http
from django.views import View
import os
from alipay import AliPay
from django.conf import settings



from Superty_mall.utils.views import LoginRequiredMixin
from orders.models import OrderInfo
from Superty_mall.utils.response_code import RETCODE
# Create your views here.

class PaymentView(LoginRequiredMixin, View):
    """对接支付宝的支付接口"""

    def get(self, request, order_id):
        """
        :param  order_id: 当前要支付的订单ID
        :return : JSON
        """

        user = request.user
        # 校验order_id
        try:
            order = OrderInfo.objects.get(order_id=order_id, user=user, status=OrderInfo.ORDER_STATUS_ENUM['UNPAID'])
        except OrderInfo.DoesNotExist:
            return http.HttpResponseForbidden('订单信息错误')


        # 创建对接支付宝接口的SDK对象
        app_private_key_string = open(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys/app_private_key.pem")).read()
        alipay_public_key_string = open(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys/alipay_public_key.pem")).read()
        alipay = AliPay(
            appid=settings.ALIPAY_APPID,
            app_notify_url=None,  # 默认回调 url
            app_private_key_string=app_private_key_string,
            # 支付宝的公钥，验证支付宝回传消息使用，不是你自己的公钥,
            alipay_public_key_string=alipay_public_key_string,
            sign_type="RSA2",  # RSA 或者 RSA2
            debug=settings.ALIPAY_DEBUG,  # 默认 False
            verbose=False,  # 输出调试数据

        )
        # SDK对象对接支付宝支付的接口，得到登录页的地址
        order_string = alipay.api_alipay_trade_page_pay(
            out_trade_no=order_id,  # 订单的编号
            total_amount=str(order.total_amount),  # 订单的支付金额
            subject="美多商城%s" % order_id,   # 订单的标题
            return_url=settings.ALIPAY_RETURN_URL,   # 同步通知的回调地址，如果不是同步通知就不传
        )
        # 拼接完整的支付宝登陆页地址
        alipay_url = settings.ALIPAY_URL + '?' + order_string

        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'alipay_url': alipay_url})
