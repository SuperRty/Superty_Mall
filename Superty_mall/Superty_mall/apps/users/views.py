from django.shortcuts import render, redirect
from django.views import View
from django import http
import re, json, logging
from django.db import DatabaseError
from django.urls import reverse
from django.contrib.auth import login, authenticate, logout
from django_redis import get_redis_connection
from django.contrib.auth.mixins import LoginRequiredMixin

from users.models import User, Address
from Superty_mall.utils.response_code import RETCODE
from Superty_mall.utils.views import LoginRequiredJSONMixin
from celery_tasks.email_verify.tasks import send_email_verify
from users.utils import generate_verify_email_url,check_verify_email_token
from goods.models import SKU
from carts.utils import merge_carts_cookies_redis
# Create your views here.

# 创建日志输出器


logger = logging.getLogger('django')



class UserBrowseHistory(LoginRequiredJSONMixin, View):
    """用户浏览记录"""

    def post(self, request):
        """保存用户商品浏览记录"""
        # 接受参数
        json_str = request.body.decode()
        json_dict = json.loads(json_str)
        sku_id = json_dict.get('sku_id')
        # print(sku_id)

        # 校验参数
        try:
            SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            return http.HttpResponseForbidden('参数sku_id错误')
        # 保存sku_id到redis
        redis_conn = get_redis_connection('history')
        user = request.user
        pl = redis_conn.pipeline()
        # 先去重
        pl.lrem('history_%s' % user.id, 0, sku_id)
        # 再保存
        pl.lpush('history_%s' % user.id, sku_id)
        # 最后截取
        pl.ltrim('history_%s' % user.id, 0, 4)
        # 执行
        pl.execute()

        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})

    def get(self, request):
        # 查询用户商品浏览记录
        user = request.user
        redis_conn = get_redis_connection('history')
        sku_ids = redis_conn.lrange('history_%s' % user.id, 0, -1)  # 0, 4
        #
        skus = []
        for sku_id in sku_ids:
            sku = SKU.objects.get(id=sku_id)
            skus.append({
                'id': sku.id,
                'name': sku.name,
                'price': sku.price,
                'default_image_url': sku.default_image.url
            })
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'skus': skus})

class ChangePasswordView(LoginRequiredMixin, View):
    """修改密码"""

    def get(self, request):
        """展示修改密码界面"""
        return render(request, 'user_center_pass.html')

    def post(self, request):
        """实现修改密码逻辑"""
        # 接收参数
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')

        # 校验参数
        if not all([old_password, new_password, new_password2]):
            return http.HttpResponseForbidden('缺少必传的参数')
        try:
            request.user.check_password(old_password)
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_pass.html', {'origin_pwd_errmsg': '原始密码错误'})
        if not re.match(r'^[0-9A-Za-z]{8,20}$', new_password):
            return http.HttpResponseForbidden('密码最少8位, 最长20位')
        if new_password != new_password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')

        # 修改密码
        try:
            request.user.set_password(new_password)
            request.user.save()
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_pass.html', {'change_pwd_errmsg': '修改密码失败'})

        # 清理状态保持信息
        logout(request)
        response = redirect(reverse('users:login'))
        response.delete_cookie('username')

        # 响应密码修改结果，重定向到登录界面
        return response

class UpdateTitleAddressView(LoginRequiredJSONMixin, View):
    """设置地址标题"""

    def put(self, request, address_id):
        """设置地址标题"""
        # 接收参数：地址标题
        json_dict = json.loads(request.body.decode())
        title = json_dict.get('title')

        try:
            # 查询地址
            address = Address.objects.get(id=address_id)

            # 设置新的地址标题
            address.title = title
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '设置地址标题失败'})

        # 4.响应删除地址结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '设置地址标题成功'})

class DefaultAddressView(LoginRequiredMixin, View):
    """设置默认地址"""

    def put(self, request, address_id):
        """实现设置默认地址逻辑"""
        try:
            # 查询出当前那个地址会作为登录用户的默认地址
            address = Address.objects.get(id=address_id)
            # 将指定的地址设置为当前登录用户的默认地址
            request.user.default_address = address
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR, 'errmsg': '设置默认地址失败'})
        return http.JsonResponse({'code':RETCODE.OK, 'errmsg': '设置默认地址成功'})

class UpdataDestoryAddressView(LoginRequiredMixin, View):
    """更新和删除地址"""

    def put(self, request, address_id):
        """更新地址"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')
        # 使用最新的地址信息覆盖指定的旧的地址信息

        # address = Address.objects.get(id=address_id)
        # # address.user = request.user,
        # address.title = receiver,
        # address.receiver = receiver,
        # address.province_id =province_id,
        # address.city_id = city_id,
        # address.district_id = district_id,
        # address.place = place,
        # address.mobile = mobile,
        # address.tel = tel,
        # address.email = email,
        # address.save()
        try:
            Address.objects.filter(id=address_id).update(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email
            )
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '修改地址失败'})
        # 响应新的地址信息给前端渲染
        address = Address.objects.get(id=address_id)
        address_dict = {
            "id": address.id,
            "title": address.title,
            "receiver": address.receiver,
            "province": address.province.name,
            "city": address.city.name,
            "district": address.district.name,
            "place": address.place,
            "mobile": address.mobile,
            "tel": address.tel,
            "email": address.email
        }
        # 响应修改地址结果：需要将新增的地址返回给前端渲染
        return http.JsonResponse({'code': RETCODE.OK, 'essmsg': '修改地址成功', 'address': address_dict})

    def delete(self, request, address_id):
        """删除地址"""
        # 实现指定地址的逻辑删除： is_delete=Ture
        try:
            address = Address.objects.get(id=address_id)
            address.is_deleted = True
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '删除地址失败'})
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '删除地址成功'})

class AddressCreateView(LoginRequiredJSONMixin, View):
    """新增地址"""

    def post(self, request):
        """实现新增地址逻辑"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        # 判断用户地址数量是否超过上限：查询当前用户的地址数量
        count = request.user.addresses.count() # 一查多，使用related_name查询
        if count > 20:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR, 'errmsg': '超出用户地址上限'})
        # 保存用户传入的地址信息
        try:
            address = Address.objects.create(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email,
            )
            # 如果登录用户没有默认的地址，我们需要指定默认地址
            if not request.user.default_address:
                request.user.default_address = address
                request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'essmsg':'新增地址失败'})

        # 新增地址成功，将新增的地址响应给前端实现局部刷新
        address_dict = {
                "id": address.id,
                "title": address.title,
                "receiver": address.receiver,
                "province": address.province.name,
                "city": address.city.name,
                "district": address.district.name,
                "place": address.place,
                "mobile": address.mobile,
                "tel": address.tel,
                "email": address.email
            }
        # 响应新增地址结果：需要将新增的地址返回给前端渲染
        return http.JsonResponse({'code': RETCODE.OK, 'essmsg': '新增地址成功', 'address': address_dict})

class AddressView(LoginRequiredMixin, View):
    """用户收货地址"""
    def get(self, request):
        """查询并展示用户地址信息"""

        # 获取当前登录用户对象
        login_user = request.user
        # 使用当前登录用户和is_deleted=False作为条件查询地址数据
        addresses = Address.objects.filter(user=login_user, is_deleted=False)
        # 将用户地址模型列表转成字典列表：因为JsonResponse和Vue.js不认识模型类型，只有Django和Jinja2模板引擎认识
        address_dict_list = []
        for address in addresses:
            address_dict = {
                "id": address.id,
                "title": address.title,
                "receiver": address.receiver,
                "province": address.province.name,
                "city": address.city.name,
                "district": address.district.name,
                "place": address.place,
                "mobile": address.mobile,
                "tel": address.tel,
                "email": address.email
            }
            address_dict_list.append(address_dict)
        # 构造上下文
        context = {
            'default_address_id': login_user.default_address_id or '0',
            'addresses': address_dict_list,
        }

        return render(request, 'user_center_site.html', context)

class VerifyEmail(View):
    """验证邮箱链接"""
    def get(self, request):
        # 接收参数
        token = request.GET.get('token')
        # 校验参数
        if not token:
            return http.HttpResponseForbidden('缺少token')
        # 从token中提取用户信息 user_id ==> user
        user = check_verify_email_token(token)
        if not user:
            return http.HttpResponseBadRequest('无效的token')
        # 将用户的email_active字段设置为Ture
        try:
            user.email_active = True
            user.save()
        except Exception as e:
            logger.error(e)
            return http.HttpResponseServerError('邮箱激活失败')
        # 响应结果：重定向到用户中心
        return redirect(reverse('users:user'))

class EmailView(View):
    """添加邮箱"""

    def put(self, request):
        # 接收参数
        json_str = request.body.decode() # body是bytes类型
        json_dict = json.loads(json_str)
        email = json_dict.get('email')
        # 校验参数
        if not email:
            return http.HttpResponseForbidden('缺少email参数')
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('参数email有误')

        # 将用户传入的邮箱保存到用户数据库的Email字段中
        try:
            request.user.email = email
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '添加邮箱失败'})

        # 发送验证邮箱短信
        verify_url = generate_verify_email_url(request.user)
        send_email_verify.delay(email, verify_url)  # 一定要记得调用delay


        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})

class UserInfoView(LoginRequiredMixin, View):
    """用户中心"""
    def get(self, request):
        """提供用户中心页面"""
        # 如果LoginRequiredMixin判断出用户已登录，那么request.user就是登陆对象
        context = {
            'username': request.user.username,
            'mobile': request.user.mobile,
            'email':request.user.email,
            'email_active': request.user.email_active,
        }
        return render(request, 'user_center_info.html', context)

class LogoutView(View):
    """用户退出登录"""

    def get(self, request):
        """实现用户退出登录的逻辑"""
        # 清楚状态保持信息
        logout(request)

        # 退出登录后重定向到首页
        response = redirect(reverse('contents:index'))

        # 删除cookies中的用户名
        response.delete_cookie('username')

        # 响应结果
        return response

class LoginView(View):
    """用户登录"""
    def get(self, request):
        """提供用户登录页面"""
        return render(request, 'login.html')
    def post(self, request):
        """实现用户登录逻辑"""
        # 接收参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        # 校验参数
        if not all([username, password]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入正确的用户名或者手机号')
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('密码最少8位, 最长20位')

        # 认证用户：使用账号查询用户是否存在，如果用户存在，再校验密码是否正确
        user = authenticate(username=username, password=password)
        if user is None:
            return render(request, 'login.html', {'account_errmsg': '账号或者密码错误'})

        # 状态保持
        login(request, user)
        # 使用remembered确定状态保持周期（实现记住登录）
        if remembered != 'on':
            # 没有记住登录：状态保持在浏览器会话结束就销毁
            request.session.set_expiry(0) # 单位是秒
        else:
            # 记住状态保持：状态保持周期为两周：默认是两周
            request.session.set_expiry(None)

        # 响应结果:重定向到首页
        next = request.GET.get('next')
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('contents:index'))

        # 为了实现在首页的右上角展示用户名信息，我们需要将用户名缓存到cookie中
        # response.set_cookie('key', 'val', 'expiry')
        response.set_cookie('username', user.username, max_age=3600 * 24 * 14)

        # 用户登录成功，合并cookie购物车到redis购物车
        # response = merge_carts_cookies_redis(request=request, user=user, response=response)

        # 响应结果:重定向到首页
        return response

class MobileCountView(View):
    """判断手机号是否重复注册"""
    def get(self, request, mobile):
        """
        :param mobile: 手机号
        :return: JSON
        """
        count = User.objects.filter(mobile=mobile).count()
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count': count})

class UsernameCountView(View):
    """判断用户名是否重复注册"""

    def get(self, request, username):
        """
        :param username: 用户名
        :return: JSON
        """
        # 实现主体业务逻辑：使用username查询对应的记录的条数(filter返回的是满足条件的结果集)
        count = User.objects.filter(username=username).count()
        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count': count})

class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """提供用户注册页面"""
        return render(request, 'register.html')

    def post(self, request):
        """实现用户注册业务逻辑"""
        # 接收参数：表单参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        # json_str = request.body.decode()  # body是bytes类型
        # json_dict = json.loads(json_str)
        mobile = request.POST.get('mobile')

        sms_code_client = request.POST.get('sms_code')
        allow = request.POST.get('allow')

        # 校验参数：前后端的校验需要分开，避免恶意用户越过前端逻辑发请求，要保证后端的安全，前后端的校验逻辑相同
        # 判断参数是否齐全:all([列表])：会去校验列表中的元素是否为空，只要有一个为空，返回false
        if not all([username, password, password2, mobile, allow]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')
        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', mobile):
            return http.HttpResponseForbidden('请输入正确的邮箱号')
        # 判断短信验证码是否输入正确
        redis_conn = get_redis_connection('verify_code')
        sms_code_server = redis_conn.get('sms_%s' % mobile)
        if sms_code_server is None:
            return render(request, 'register.html', {'sms_code_errmsg': '验证码已失效'})
        if sms_code_server.decode() != sms_code_client:
            return render(request, 'register.html', {'sms_code_errmsg': '验证码输入错误'})
        # 判断是否勾选用户协议
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')

        # 保存注册数据：是注册业务的核心
        # return render(request, 'register.html', {'register_errmsg': '注册失败'})
        try:
            user = User.objects.create_user(username=username, password=password, mobile=mobile)
        except DatabaseError:
            return render(request, 'register.html', {'register_errmsg':'注册失败'})

        # 实现状态保持
        login(request, user)

        # 响应结果:重定向到首页
        response = redirect(reverse('contents:index'))

        # 为了实现在首页的右上角展示用户名信息，我们需要将用户名缓存到cookie中
        # response.set_cookie('key', 'val', 'expiry')
        response.set_cookie('username', user.username, max_age=3600 * 24 * 14)

        # 响应结果:重定向到首页
        return response