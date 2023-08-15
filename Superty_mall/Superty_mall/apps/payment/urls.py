from django.conf.urls import url

from . import views



urlpatterns = [
    # 支付
   url(r'payment/(?P<order_id>\d+)/', views.PaymentView.as_view()),
]