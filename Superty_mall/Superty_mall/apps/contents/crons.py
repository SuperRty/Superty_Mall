# 静态化首页
from collections import OrderedDict
from django.shortcuts import render
from django.template import loader
import os
from django.conf import settings

from .utils import get_categories
from .models import ContentCategory


def generate_static_index_html():
    """静态化首页"""

    # 查询首页的数据
    # 查询并展示商品分类
    categories = get_categories()

    # 查询首页广告数据
    # 查询所有的广告类别
    contents = OrderedDict()
    content_categories = ContentCategory.objects.all()
    for content_category in content_categories:
        contents[content_category.key] = content_category.content_set.filter(status=True).order_by(
            'sequence')  # 查询出未下架的广告并展示

    # 构造上下文
    context = {
        'categories': categories,
        'contents': contents
    }

    # 渲染到模板
    # render工作原理：1.先获取模板文件  2.再使用上下文渲染模板文件
    template = loader.get_template('index.html')
    html_text = template.render(context)

    # 将模板文件写入到静态路径
    file_path = os.path.join(settings.STATICFILES_DIRS[0], 'index.html')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html_text)