from django.conf.urls import url

from . import views



urlpatterns = [
        # 订单结算
        url('^orders/settlement/$', views.OrderSettlementView.as_view(), name='settelment'),
        # 订单提交
        url('^orders/commit/$', views.OrderCommitView.as_view()),
        # 订单提交成功页面
        url('^orders/success/$', views.OrderSuccessView.as_view()),
        # 我的订单页面
        url('^orders/info/(?P<page_num>\d+)/$', views.UserOrderInfoView.as_view()),
]
