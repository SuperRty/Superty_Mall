import base64
import json
import pickle
from django import http
from django.shortcuts import render
from django.views import View
from django_redis import get_redis_connection


from goods.models import SKU
from Superty_mall.utils.response_code import RETCODE


class CartsSelectAllView(View):
    """全选购物车"""

    def put(self, request):
            # 接收参数
            json_dict = json.loads(request.body.decode())
            selected = json_dict.get('selected', True)

            # 校验参数
            if selected:
                if not isinstance(selected, bool):
                    return http.HttpResponseForbidden('参数selected有误')

            # 判断用户是否登录
            user = request.user
            if user is not None and user.is_authenticated:
                # 用户已登录，操作redis购物车
                redis_conn = get_redis_connection('carts')
                pl = redis_conn.pipeline()
                # 获取所有的记录
                redis_cart = pl.hgetall('carts_%s' % user.id)
                # 获取字典中所有的key
                redis_sku_ids = redis_cart.keys()
                # 判断用户是否勾选
                if selected:
                    # 全选
                    pl.sadd('selected_%s' % user.id, *redis_sku_ids)
                else:
                    # 取消全选
                    pl.srem('selected_%s' % user.id, *redis_sku_ids)
                pl.execute()
                # 响应结果
                return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
            else:
                # 如果用户未登录，操作cookie购物车
                # 获取cookie中的购物车数据，并判断是否有购物车数据
                cart_str = request.COOKIES.get('carts')

                response = http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
                if cart_str:
                    # 将cart_str转成bytes类型的字符串
                    cart_str_bytes = cart_str.encode()
                    # 将cart_str_bytes转成bytes类型的字典
                    cart_dict_bytes = base64.b64decode(cart_str_bytes)
                    # 将cart_dict_bytes转成真正的字典
                    cart_dict = pickle.loads(cart_dict_bytes)

                    # 遍历所有的购物车数据
                    for sku_id in cart_dict:
                        cart_dict[sku_id]['selected'] = selected  # Ture/False
                    # 将cart_dict转成bytes类型的字典
                    cart_dict_bytes = pickle.dumps(cart_dict)
                    # 将cart_dict_bytes转成bytes类型的字符串
                    cart_str_bytes = base64.b64encode(cart_dict_bytes)
                    # 将cart_str_bytes转成字符串
                    cookie_cart_str = cart_str_bytes.decode()

                    # 重新将购物车数据写入cookie
                    response.set_cookie('carts', cookie_cart_str)
                return response

class CartsView(View):
    """购物车管理"""

    def post(self, request):
        """保存购物车"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        sku_id = json_dict.get('sku_id')
        count = json_dict.get('count')
        selected = json_dict.get('selected', True)  # 可选
        # 校验参数
        # 判断参数是否齐全
        if not all([sku_id, count]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 校验sku_id是否合法
        try:
            SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            return http.HttpResponseForbidden('参数sku_id错误')
        # 校验count是否是数字
        try:
            count = int(count)
        except Exception as e:
            return http.HttpResponseForbidden('参数count错误')
        # 校验勾选是否是bool
        if selected:
            if not isinstance(selected, bool):
                return http.HttpResponseForbidden('参数selected错误')

        # 判断用户是否登录
        user = request.user
        if user.is_authenticated:
            # 如果用户已登录， 操作Redis数据库
            redis_conn = get_redis_connection('carts')
            pl = redis_conn.pipeline()
            # 需要以增量计算的形式保存商品数据
            pl.hincrby('carts_%s' % user.id, sku_id, count)
            # 保存商品勾选状态
            if selected:
                pl.sadd('selected_%s' % user.id, sku_id)
            # 执行
            pl.execute()
            # 响应结果
            return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
        else:
            # 如果用户未登录，操作cookie购物车
            # 获取cookie中的购物车数据，并判断是否有购物车数据
            cart_str = request.COOKIES.get('carts')
            if cart_str:
                # 将cart_str转成bytes类型的字符串
                cart_str_bytes = cart_str.encode()
                # 将cart_str_bytes转成bytes类型的字典
                cart_dict_bytes = base64.b64decode(cart_str_bytes)
                # 将cart_dict_bytes转成真正的字典
                cart_dict = pickle.loads(cart_dict_bytes)
            else:
                cart_dict = {}

            # 判断当前要添加的商品在cart_dict中是否存在
            if sku_id in cart_dict:
                # 购物车已存在，增量计算
                origin_count = cart_dict[sku_id]['count']
                count += origin_count

            cart_dict[sku_id] = {
                'count': count,
                'selected': selected,
            }
            # 将cart_dict转成bytes类型的字典
            cart_dict_bytes = pickle.dumps(cart_dict)
            # 将cart_dict_bytes转成bytes类型的字符串
            cart_str_bytes = base64.b64encode(cart_dict_bytes)
            # 将cart_str_bytes转成字符串
            cookie_cart_str = cart_str_bytes.decode()

            # 将新的购物车数据写入到cookie中
            response = http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
            response.set_cookie('carts', cookie_cart_str)
             # 响应结果
            return response

    def get(self, request):
        """查询购物车"""
        # 接收和校验参数
        # 判断用户是否登录
        user = request.user
        if user.is_authenticated:
            # 用户已登录，查询redis购物车
            redis_conn = get_redis_connection('carts')
            # 获取redis中的购物车数据
            redis_cart = redis_conn.hgetall('carts_%s' % user.id)
            # 获取redis中的选中状态
            cart_selected = redis_conn.smembers('selected_%s' % user.id)

            # 将redis中的数据构造成跟cookie中的格式一致，方便统一查询
            cart_dict = {}
            for sku_id, count in redis_cart.items():
                cart_dict[int(sku_id)] = {
                    'count': int(count),
                    'selected': sku_id in cart_selected
                }


        else:
            # 如果用户未登录，查询cookie购物车
            # 获取cookie中的购物车数据，并判断是否有购物车数据
            cart_str = request.COOKIES.get('carts')
            if cart_str:
                # 将cart_str转成bytes类型的字符串
                cart_str_bytes = cart_str.encode()
                # 将cart_str_bytes转成bytes类型的字典
                cart_dict_bytes = base64.b64decode(cart_str_bytes)
                # 将cart_dict_bytes转成真正的字典
                cart_dict = pickle.loads(cart_dict_bytes)
            else:
                cart_dict = {}
        # 构造数据结构
        # 获取字典中所有的key，（sku_id）
        sku_ids = cart_dict.keys()

        # 一次性查询出所有的skus
        skus = SKU.objects.filter(id__in=sku_ids)
        cart_skus = []
        for sku in skus:
            cart_skus.append({
                'id': sku.id,
                'name': sku.name,
                'count': cart_dict.get(sku.id).get('count'),
                'selected': str(cart_dict.get(sku.id).get('selected')),  # 将True，转'True'，方便json解析
                'default_image_url': sku.default_image.url,
                'price': str(sku.price),  # 从Decimal('10.2')中取出'10.2'，方便json解析
                'amount': str(sku.price * cart_dict.get(sku.id).get('count')),
            })

        context = {
            'cart_skus': cart_skus,
        }

        # 渲染购物车页面
        return render(request, 'cart.html', context)

    def put(self, request):
        """修改购物车"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        sku_id = json_dict.get('sku_id')
        count = json_dict.get('count')
        selected = json_dict.get('selected', True)

        # 判断参数是否齐全
        if not all([sku_id, count]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断sku_id是否存在
        try:
            sku = SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            return http.HttpResponseForbidden('商品sku_id不存在')
        # 判断count是否为数字
        try:
            count = int(count)
        except Exception:
            return http.HttpResponseForbidden('参数count有误')
        # 判断selected是否为bool值
        if selected:
            if not isinstance(selected, bool):
                return http.HttpResponseForbidden('参数selected有误')

        # 判断用户是否登录
        user = request.user
        if user.is_authenticated:
            # 用户已登录，修改redis购物车
            redis_conn = get_redis_connection('carts')
            pl = redis_conn.pipeline()
            # 由于后端收到的数据是最终的结果，所以覆盖写入
            pl.hset('carts_%s'  % user.id, sku_id, count)
            # 修改勾选状态
            if selected:
                pl.sadd('selected_%s' % user.id, sku_id)
            else:
                pl.srem('selected_%s' % user.id, sku_id)
            # 执行
            pl.execute()
            # 创建响应对象
            cart_sku = {
                'id': sku_id,
                'count': count,
                'selected': selected,
                'name': sku.name,
                'default_image_url': sku.default_image.url,
                'price': sku.price,
                'amount': sku.price * count,
            }
            return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '修改购物车成功', 'cart_sku': cart_sku})
        else:
            # 用户未登录，修改cookie购物车
            # 获取cookie中的购物车数据，并判断是否有购物车数据
            cart_str = request.COOKIES.get('carts')
            if cart_str:
                # 将cart_str转成bytes类型的字符串
                cart_str_bytes = cart_str.encode()
                # 将cart_str_bytes转成bytes类型的字典
                cart_dict_bytes = base64.b64decode(cart_str_bytes)
                # 将cart_dict_bytes转成真正的字典
                cart_dict = pickle.loads(cart_dict_bytes)
            else:
                cart_dict = {}

            # 由于后端收到的的是最终的结果，所以‘覆盖写入’
            cart_dict[sku_id] = {
                'count': count,
                'selected': selected,
            }

            cart_sku = {
                'id': sku_id,
                'count': count,
                'selected': selected,
                'name': sku.name,
                'default_image_url': sku.default_image.url,
                'price': sku.price,
                'amount': sku.price * count,
            }

            # 将cart_dict转成bytes类型的字典
            cart_dict_bytes = pickle.dumps(cart_dict)
            # 将cart_dict_bytes转成bytes类型的字符串
            cart_str_bytes = base64.b64encode(cart_dict_bytes)
            # 将cart_str_bytes转成字符串
            cookie_cart_str = cart_str_bytes.decode()

            # 将新的购物车数据写入到cookie中
            response = http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'cart_sku': cart_sku})
            response.set_cookie('carts', cookie_cart_str)
            # 响应结果
            return response

    def delete(self, request):
        """删除购物车"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        sku_id = json_dict.get('sku_id')

        # 判断sku_id是否存在
        try:
            SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            return http.HttpResponseForbidden('商品不存在')

        # 判断用户是否登录
        user = request.user
        if user is not None and user.is_authenticated:
            # 用户未登录，删除redis购物车
            redis_conn = get_redis_connection('carts')
            pl = redis_conn.pipeline()

            # 删除hash购物车商品记录
            pl.hdel('carts_%s' % user.id, sku_id)
            # 同步移除勾选状态
            pl.srem('selected_%s' % user.id, sku_id)
            pl.execute()

            return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
        else:
            # 用户未登录，删除cookie购物车
            # 获取cookie中的购物车数据，并判断是否有购物车数据
            cart_str = request.COOKIES.get('carts')
            if cart_str:
                # 将cart_str转成bytes类型的字符串
                cart_str_bytes = cart_str.encode()
                # 将cart_str_bytes转成bytes类型的字典
                cart_dict_bytes = base64.b64decode(cart_str_bytes)
                # 将cart_dict_bytes转成真正的字典
                cart_dict = pickle.loads(cart_dict_bytes)
            else:
                cart_dict = {}

            # 构造响应对象
            response = http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})
            # 删除字典中指定的key所对应的记录
            if sku_id in cart_dict:
                del cart_dict[sku_id]

                # 将cart_dict转成bytes类型的字典
                cart_dict_bytes = pickle.dumps(cart_dict)
                # 将cart_dict_bytes转成bytes类型的字符串
                cart_str_bytes = base64.b64encode(cart_dict_bytes)
                # 将cart_str_bytes转成字符串
                cookie_cart_str = cart_str_bytes.decode()

                # 写入新的cookie
                response.set_cookie('carts', cookie_cart_str)
            return response
