# 定义任务
from celery_tasks.main import celery_app
import logging
import base64
import smtplib
from email.header import Header
from email.mime.text import MIMEText

# 创建日志输出器
logger = logging.getLogger('django')


# 使用装饰器装饰异步任务，保证celery识别任务
@celery_app.task(bind=True, name='send_email_sms', retry_backoff=3)
def send_email_sms(self, to_email, sms_code):
    """
    发送验证邮箱邮件
    :param to_email: 收件人邮箱
    :param verify_url: 验证链接
    :return: None
    """
    fromAddr = '1434726766@qq.com'  # 发送邮件地址
    password = 'ahgnaudfsihshihe'  # SMTP服务的密码, 就是上述图中的授权码
    toAddr = to_email  # 目的邮件地址
    subject = "SuperHT商城<1434726766@qq.com>"
    fromName = "SuperHT商城"
    sender = '1434726766@qq.com'
    content = '<p>尊敬的用户您好！</p>' \
              '<p>感谢您使用接收该邮件。</p>' \
              '<p>您的邮箱为：%s 。请输入以下验证码(有效期为5分钟)：</p>' \
              '<p>您的验证码为：%s</p>' % (to_email, sms_code)
    # send_mail('标题', '普通邮件正文', '发件人', '收件人列表', '富文本邮件正文(html)')

    mail = MIMEText(content, 'html', 'utf-8')  # 使用MIMEText()构造一个文本格式的邮件

    # 构造邮件头From
    # 汉字转base64
    fromName64 = base64.b64encode(bytes(fromName, 'utf-8'))
    # b'xxxx'转为'xxxx'
    fromName64str = str(fromName64, 'utf-8')
    # 尖括号拼接用双引号
    fromNamestr = '"=?utf-8?B?' + fromName64str + '=?=" <' + sender + ">"
    mail['From'] = Header(fromNamestr)

    mail['To'] = Header(toAddr, 'utf-8')  # 构造邮件头To
    mail['Subject'] = Header(subject, 'utf-8')  # 构造邮件主题

    try:
        # smtp= smtplib.SMTP()						# 创建SMTP实例
        # smtp.connect('smtp.qq.com') 				# 连接SMTP服务器
        smtp = smtplib.SMTP_SSL("smtp.qq.com")  # 此处直接一步到位
        smtp.login(fromAddr, password)  # 登录SMTP服务
        smtp.sendmail(fromAddr, toAddr, mail.as_string())  # 通过SMTP服务器发送邮件
        smtp.quit()
        print('发送邮件成功')
    except Exception as e:
        logger.error(e)
        # 有异常自动重试三次
        raise self.retry(exc=e, max_retries=8)

