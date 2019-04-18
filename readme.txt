当前项目是SSO登陆的sp端代码
idp端代码：https://github.com/ningObito/SSO_IDP.git

域名设置
   sp:  www.obito-sp.com
   idp:www.obito-idp.com

请在sp和idp的机器上修改C:\Windows\System32\drivers\etc\hosts,在文件最下面加上
127.0.0.1 www.obito-idp.com    // ip地址根据实际情况修改，这里是将idp和sp放在一台主机上跑
127.0.0.1 www.obito-sp.com


1.导入eclipse中。
2.将项目添加到tomcat中。
3.启动tomcat
4.打开浏览器访问
   http://www.obito-sp.com:8080/testSp/index.jsp

5.Idp端输入用户名
    obito/123456
6.认证成功

