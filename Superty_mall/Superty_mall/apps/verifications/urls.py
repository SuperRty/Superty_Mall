from django.conf.urls import url

from . import views


urlpatterns = [
    # 图形验证码
    url(r'^image_codes/(?P<uuid>[\w-]+)/$', views.ImageCodeView.as_view()),
    # 短信验证码
    url(r'^sms_codes/(?P<mobile>[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2})/$', views.SMSCodeView.as_view()),
]