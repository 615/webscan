Webscan使用方式：

通过获取爬虫爬取结果得文件。来进行扫描，格式为：

python3  webscan.py  -f  xxx.txt

# 数据格式为json文件。 解析json文件，进行扫描。默认支持 puppeteer 爬虫生成得json文件。

例如：
{"url":"http://192.168.1.1:8000/WebGoat/SqlInjection/attack5","method":"POST","headers":{"Accept":"*/*","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8","Cookie":"JSESSIONID=NGwE2ct2wsIHi6eac-Paw0lP82O7PGLZYL1iXuSz","Referer":"http://192.168.1.1:8000/WebGoat/start.mvc","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/102.0.5002.0 Safari/537.36","X-Requested-With":"XMLHttpRequest"},"cookies":[{"name":"JSESSIONID","value":"NGwE2ct2wsIHi6eac-Paw0lP82O7PGLZYL1iXuSz","domain":"192.168.1.1","path":"/WebGoat","expires":-1,"size":50,"httpOnly":false,"secure":false,"session":true,"sameParty":false,"sourceScheme":"NonSecure","sourcePort":8080}],"body":"query=test"}

如果要使用chromium 进行dom-xss检测，需要在config.py 中配置浏览器得路径。