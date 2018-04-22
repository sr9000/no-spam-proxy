//socks4/5 http/https no spam proxy server

#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

//#define DEBUG
#define WRITE_BLOCK

#ifdef DEBUG
	//#define DEBUG_READ_CLIENT_REQUEST
	//#define DEBUG_STREAM
	#define DEBUG_TRANSMISSION
	#define DEBUG_SOCKSVERSION
	#define DEBUG_FIND_URL
#endif

HANDLE debug;
int totalh, totall, totalc;
int blockh, blockl, blockc;

enum OperationResult
{
	OR_SUCCESS = 0x1,
	OR_FAIL = 0x2
};

//stream interface
class Stream
{
public:
	#ifdef DEBUG
		LPVOID val;
	#endif
	virtual ~Stream(){}
	//read n byte into buf
	virtual OperationResult read(char *buf, size_t n, int d = 0) = 0;
	//read n byte into buf, but keep it in stream
	virtual OperationResult view(char *buf, size_t n) = 0;
	//read n byte into buf
	virtual OperationResult write(const char *buf, size_t n, int d = 0) = 0;
};
//socket stream
class SocketStream
	: public Stream
{
private:
	SOCKET *ps;
public:
	SocketStream(SOCKET *s)
		: ps(s)
	{}
	
	OperationResult read(char *buf, size_t n, int d = 0)
	{
		#ifdef DEBUG_STREAM
			buf[0] = 1;
			if (d)
			{
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012- S5CR\t before buf[0](%d)\n", val, buf[0]);
				ReleaseMutex(debug);
			}
		#endif
		int recvResult = recv(*ps, buf, n, 0);
		#ifdef DEBUG_STREAM
			if (d)
			{
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012- S5CR\t after buf[0](%d)\n", val, buf[0]);
				ReleaseMutex(debug);
			}
		#endif
		if (recvResult == SOCKET_ERROR)
		{
			#ifdef DEBUG_STREAM
				if (d)
				{
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:012- S5CR\t SOCKET_ERROR\n", val);
					ReleaseMutex(debug);
				}
			#endif
			return OR_FAIL;
		}
		if (recvResult != n)
		{
			#ifdef DEBUG_STREAM
				if (d)
				{
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:012- S5CR\t recvResult(%d) != n(%d)\n", val, recvResult, n);
					ReleaseMutex(debug);
				}
			#endif
			return OR_FAIL;
		}
		return OR_SUCCESS;
	}
	
	OperationResult view(char *buf, size_t n)
	{
		int recvResult = recv(*ps, buf, n, MSG_PEEK);
		if (recvResult == SOCKET_ERROR) return OR_FAIL;
		if (recvResult != n) return OR_FAIL;
		return OR_SUCCESS;
	}
	
	OperationResult write(const char *buf, size_t n, int d = 0)
	{
		#ifdef DEBUG_STREAM
			if (d)
			{
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x: write\t ", val);
				for (size_t i = 0; i < n; ++i)
				{
					printf("%02X ", buf[i]);
				}
				printf("\n");
				ReleaseMutex(debug);
			}
		#endif
		int sendResult = send(*ps, buf, n, 0);
		if (sendResult == SOCKET_ERROR) return OR_FAIL;
		if (sendResult != n) return OR_FAIL;
		return OR_SUCCESS;
	}
};

//RFC1928 socks5
class SOCKS5_ClientGreeting
{
public:
	unsigned char version;
	unsigned char nMethods;
	unsigned char listMethods[256];
	
	OperationResult read(Stream *s)
	{
		OperationResult r;
		r = s->read((char*)&version, 1);
		if (r == OR_FAIL) return OR_FAIL;
		#ifdef DEBUG_SOCKSVERSION
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:ClientGreeting\t SOCKS(%d)\n", s->val, version);
			ReleaseMutex(debug);
		#endif
		if (version != 0x05) return OR_FAIL;
		r = s->read((char*)&nMethods, 1);
		if (r == OR_FAIL) return OR_FAIL;
		if (nMethods == 0) return OR_FAIL;
		r = s->read((char*)&listMethods[0], nMethods);
		if (r == OR_FAIL) return OR_FAIL;
		return OR_SUCCESS;
	}
};

class SOCKS5_ServerGreeting
{
public:
	unsigned char version;
	unsigned char method;
	
	SOCKS5_ServerGreeting()
	{
		version = 0;
		method = 0;
	}
	
	void init_default()
	{
		version = 0x05;
		method = 0x00;  //method=0x00 is no authentication required
	}
	
	OperationResult serialize(char *buf)
	{
		buf[0] = (char)version;
		buf[1] = (char)method;
		return OR_SUCCESS;
	}
	
	size_t serializedSize()
	{
		return 2;
	}
};

enum SOCKS5_AddressType
{
	SOCKS5_IPv4 = 0x01,
	SOCKS5_DOMENNAME = 0x03,
	SOCKS5_IPv6 = 0x04
};

class SOCKS5_Address
{
public:
	SOCKS5_AddressType atyp;
	unsigned char ipv4[4];
	size_t ldomenname;
	char domenname[256];
	unsigned char ipv6[16];
	WORD port;
	
	OperationResult set_ipv4_from_int(unsigned int addr)
	{
		atyp = SOCKS5_IPv4;
		ipv4[3] = (char)(addr & 0xff);
		ipv4[2] = (char)((addr >> 4) & 0xff);
		ipv4[1] = (char)((addr >> 8) & 0xff);
		ipv4[0] = (char)((addr >> 12) & 0xff);
		return OR_SUCCESS;
	}
	
	OperationResult set_ipv4_from_string(const char *addr)
	{
		//check string
		int p = 0;
		int cpoints = 0;
		while(addr[p] != 0 && p < 16)
		{
			if (addr[p] == '.') ++cpoints;
			
			if (!(   (addr[p] >= '0' && addr[p] <= '9')
			       || addr[p] == '.'))
			{
				return OR_FAIL;
			}
			++p;
		}
		if (p >= 16) return OR_FAIL;
		if (cpoints != 3) return OR_FAIL;
		//set address
		unsigned int _1, _2, _3, _4;
		sscanf(addr, "%u.%u.%u.%u", &_1, &_2, &_3, &_4);
		atyp = SOCKS5_IPv4;
		ipv4[3] = (char)(_4 & 0xff);
		ipv4[2] = (char)(_3 & 0xff);
		ipv4[1] = (char)(_2 & 0xff);
		ipv4[0] = (char)(_1 & 0xff);
		return OR_SUCCESS;
	}
	
	OperationResult set_domenname_from_string(const char *name)
	{
		//check string
		int p = 0;
		while(name[p] != 0 && p < 254) ++p;
		if (p >= 254) return OR_FAIL;
		//set domen name
		atyp = SOCKS5_DOMENNAME;
		strcpy(domenname, name);
		ldomenname = strlen(name);
		return OR_SUCCESS;
	}
	
	OperationResult read(Stream *s)
	{
		OperationResult r;
		{//read type
			unsigned char ch_atyp;
			r = s->read((char*)&ch_atyp, 1);
			if (r == OR_FAIL) return OR_FAIL;
			atyp = (SOCKS5_AddressType)ch_atyp;
		}
		switch (atyp)
		{
			case SOCKS5_IPv4:
				{//read ipv4
					r = s->read((char*)&ipv4[0], 4);
					if (r == OR_FAIL) return OR_FAIL;
				}
				break;
			case SOCKS5_DOMENNAME:
				{//domen name
					unsigned char l;
					r = s->read((char*)&l, 1);
					if (r == OR_FAIL) return OR_FAIL;
					if (l == 0) return OR_FAIL;
					ldomenname = (size_t)l;
					r = s->read((char*)&domenname[0], ldomenname);
					if (r == OR_FAIL) return OR_FAIL;
					domenname[ldomenname] = 0;
				}
				break;
			case SOCKS5_IPv6:
				{//read ipv6
					r = s->read((char*)&ipv6[0], 16);
					if (r == OR_FAIL) return OR_FAIL;
				}
				break;
			default:
				return OR_FAIL;
		}
		//port
		r = s->read((char*)&port, 2);
		if (r == OR_FAIL) return OR_FAIL;
		return OR_SUCCESS;
	}
	
	OperationResult serialize(char *buf)
	{
		switch(atyp)
		{
			case SOCKS5_IPv4:
				{
					buf[0] = (char)SOCKS5_IPv4;
					memcpy(&buf[1], &ipv4[0], 4);
					memcpy(&buf[5], &port, 2);
				}
				break;
			case SOCKS5_DOMENNAME:
				{
					buf[0] = (char)SOCKS5_DOMENNAME;
					buf[1] = (char)ldomenname;
					memcpy(&buf[2], &domenname[0], ldomenname);
					memcpy(&buf[ldomenname + 2], &port, 2);
				}
				break;
			case SOCKS5_IPv6:
				{
					buf[0] = (char)SOCKS5_IPv6;
					memcpy(&buf[1], &ipv6[0], 16);
					memcpy(&buf[17], &port, 2);
				}
				break;
			default:
				return OR_FAIL;
		}
		return OR_SUCCESS;
	}
	
	size_t serializedSize()
	{
		switch(atyp)
		{
			case SOCKS5_IPv4: return 7;
			case SOCKS5_DOMENNAME: return 4 + ldomenname;
			case SOCKS5_IPv6: return 19;
			default: return 0;
		}
	}
};

enum SOCKS5_CMD
{
	SOCKS5_CONNECT = 0x01,
	SOCKS5_BIND = 0x02,
	SOCKS5_UDP = 0x03
};

class SOCKS5_ClientRequest
{
public:
	unsigned char version;
	SOCKS5_CMD command;
	SOCKS5_Address address;
	
	OperationResult read(Stream *s)
	{
		OperationResult r;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			int id = 0;
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t Read version...\n", s->val, ++id);
			ReleaseMutex(debug);
		#endif
		r = s->read((char*)&version, 1, 1);
		#ifdef DEBUG_SOCKSVERSION
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:ClientRequest\t SOCKS(%d)\n", s->val, version);
			ReleaseMutex(debug);
		#endif
		if (r == OR_FAIL) return OR_FAIL;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t read ok, what about version(%d)?...\n", s->val, ++id, version);
			ReleaseMutex(debug);
		#endif
		if (version != 0x05) return OR_FAIL;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t Done reading version\n", s->val, ++id);
			ReleaseMutex(debug);
		#endif
		{//command
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Read command...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			unsigned char cmd;
			r = s->read((char*)&cmd, 1);
			if (r == OR_FAIL) return OR_FAIL;
			command = (SOCKS5_CMD)cmd;
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done reading command...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		{//reserve
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Read reserve...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			char nul;
			r = s->read((char*)&nul, 1);
			if (r == OR_FAIL) return OR_FAIL;
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done reading reserve...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		#ifdef DEBUG_READ_CLIENT_REQUEST
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t Read address...\n", s->val, ++id);
			ReleaseMutex(debug);
		#endif
		return address.read(s);
	}
};

enum SOCKS5_REP
{
	REP_SUCCESS = 0x00,
	REP_SERV_ERROR = 0x01,
	REP_CONNECT_FORBIDDEN = 0x02,
	REP_NET_NOT_AVAILABLE = 0x03,
	REP_HOST_NOT_AVAILABLE = 0x04,
	REP_CONNECT_REFUSED = 0x05,
	REP_TTL_EXPIRED = 0x06,
	REP_CMD_NOT_SUPPORT = 0x07,
	REP_ATYP_NOT_SUPPORT = 0x08
};

class SOCKS5_ServerResponse
{
public:
	unsigned char version;
	SOCKS5_REP report;
	SOCKS5_Address address;
	
	SOCKS5_ServerResponse()
	{
		version = 0;
		report = REP_SUCCESS;
		address.set_ipv4_from_int(0);
	}
	
	void init_default()
	{
		version = 0x05;
	}
	
	OperationResult serialize(char *buf)
	{
		buf[0] = (char)version;
		switch(report)
		{
			case REP_SUCCESS:
			case REP_SERV_ERROR:
			case REP_CONNECT_FORBIDDEN:
			case REP_NET_NOT_AVAILABLE:
			case REP_HOST_NOT_AVAILABLE:
			case REP_CONNECT_REFUSED:
			case REP_TTL_EXPIRED:
			case REP_CMD_NOT_SUPPORT:
			case REP_ATYP_NOT_SUPPORT:
				buf[1] = (char)report;
				break;
			default:
				return OR_FAIL;
		}
		buf[2] = 0x00;  //reserved field
		address.serialize(&buf[3]);
		return OR_SUCCESS;
	}
	
	size_t serializedSize()
	{
		switch(report)
		{
			case REP_SUCCESS:
			case REP_SERV_ERROR:
			case REP_CONNECT_FORBIDDEN:
			case REP_NET_NOT_AVAILABLE:
			case REP_HOST_NOT_AVAILABLE:
			case REP_CONNECT_REFUSED:
			case REP_TTL_EXPIRED:
			case REP_CMD_NOT_SUPPORT:
			case REP_ATYP_NOT_SUPPORT:
				return 3 + address.serializedSize();
			default:
				return 0;
		}
	}
};

class SOCKS4_ClientRequest
{
public:
	unsigned char version;
	unsigned char command;
	DWORD port;
	char ipv4[4];
	
	OperationResult read(Stream *s)
	{
		OperationResult r;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			int id = 0;
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t Read version...\n", s->val, ++id);
			ReleaseMutex(debug);
		#endif
		r = s->read((char*)&version, 1, 1);
		#ifdef DEBUG_SOCKSVERSION
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:ClientRequest\t SOCKS(%d)\n", s->val, version);
			ReleaseMutex(debug);
		#endif
		if (r == OR_FAIL) return OR_FAIL;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t read ok, what about version(%d)?...\n", s->val, ++id, version);
			ReleaseMutex(debug);
		#endif
		if (version != 0x04) return OR_FAIL;
		#ifdef DEBUG_READ_CLIENT_REQUEST
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:012-%03d S5CR\t Done reading version\n", s->val, ++id);
			ReleaseMutex(debug);
		#endif
		{//command
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Read command...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			r = s->read((char*)&command, 1);
			if (r == OR_FAIL) return OR_FAIL;
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done reading command...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		{//port
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Read port...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			r = s->read((char*)&port, 2);
			if (r == OR_FAIL) return OR_FAIL;
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done reading port...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		{//address
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Read address...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			r = s->read((char*)&(ipv4[0]), 4);
			if (r == OR_FAIL) return OR_FAIL;
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done reading address...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		{//sckip for '\0'
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Sckip while not null...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
			char x;
			do
			{
				r = s->read((char*)&x, 1);
				if (r == OR_FAIL) return OR_FAIL;
			} while(x != 0);
			#ifdef DEBUG_READ_CLIENT_REQUEST
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:012-%03d S5CR\t Done sckip while not null...\n", s->val, ++id);
				ReleaseMutex(debug);
			#endif
		}
		return OR_SUCCESS;
	}
};

class SOCKS4_ServerResponse
{
public:
	unsigned char command; //0x5a succ, 0x5b err
	
	OperationResult serialize(char *buf)
	{
		buf[0] = 0;
		buf[1] = (char)command;
		for (int i = 2; i < 8; ++i)
			buf[i] = 0;
		return OR_SUCCESS;
	}
	
	size_t serializedSize()
	{
		return 8;
	}
};

//ignore data
void FlushRecvBufferUntil(SOCKET s, char condition)
{
	int iReceiveRes;
	char cDummy;
	do
	{
		iReceiveRes = recv(s, &cDummy, sizeof(cDummy), 0);
	} while (iReceiveRes != SOCKET_ERROR && iReceiveRes != 0 && cDummy != condition);
}

const int MAX_RECORDS = 10000000;
const unsigned char binP = 0x00;//0x00 - passed
const unsigned char binB = 0xFF;//0xff - blocked
const unsigned char binN = 0x55;//0x55 - no data
const unsigned char binID[4] = {(unsigned char)0xaa, (unsigned char)0xff, (unsigned char)0x55, (unsigned char)0x00};
#pragma push(1)
struct binRecord
{
	//0x00 - passed
	//0xff - blocked
	//0x55 - no data
	unsigned char current;
	
	//A-Z     26//erased
	//a-z     26
	//0-9     10
	//'-' '.'  2
	//'_'      1
	//total:  39
	uint32_t next[39];
};
struct binFileHeader
{
	char id[4];
	char hash[5];
	uint32_t countRecs;
};
#pragma pop
//this function havent checks to improve perfomance
inline int getIdByLetter(char letter)
{
	letter = (char)tolower(letter);
	if (letter >= 'a' && letter <= 'z') //most probability
		return (int)(letter - 'a');
	if (letter >= '0' && letter <= '9') //less probability
		return (int)(letter - '0') + 26;
	if (letter == '.') return 36;
	if (letter == '-') return 37;
	if (letter == '_') return 38;
	
	return 0;
	//usually url is case-insensitive
	//because this heavy check is last
	//in despite of 26 letters is also probably
	//as part of low case letters
	/*if (letter >= 'A' && letter <= 'Z')
		return (int)(letter - 'A') + 38;*/
}
binRecord *records;

void reverse(char *s)
{
    int length = strlen(s) ;
    int c, i, j;

    for (i = 0, j = length - 1; i < j; i++, j--)
    {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

OperationResult checkUrl(char *url)
{
	reverse(url);
	int len = strlen(url);
	int p = 0;
	for (int i = 0; i < len; ++i)
	{
		int id = getIdByLetter(url[i]);
		if (records[p].next[id] > 0)
		{
			p += records[p].next[id];
		}
		else
		{
			//not found, no data
			reverse(url);
			return OR_SUCCESS;
		}
	}
	reverse(url);
	if (records[p].current == binP) return OR_SUCCESS;
	return OR_FAIL;
}

//function for new thread
#define _Thread(x) unsigned long __stdcall x (LPVOID pParam)

#ifdef MinGW
	u_long BLK = 0;
	u_long NONBLK = 1;
#else
	unsigned int BLK = 0;
	unsigned int NONBLK = 1;
#endif

const int addr = INADDR_LOOPBACK;//INADDR_LOOPBACK is 127.0.0.1(localhost)
const char saddr[] = "127.0.0.1";
const int port = 7766;

struct _LeaveException {};

inline bool idn(char s)
{
	if (s >= 'a' && s <= 'z'
	 || s >= 'A' && s <= 'Z'
	 || s >= '0' && s <= '9'
	 || s == '-' || s == '.' || s == '_'
	) return true;
	return false;
}

OperationResult find160301(const char* inbuf, int len, char *url, int ml)
{
	if (!(inbuf[0] == 0x16 && inbuf[1] == 0x03 && inbuf[2] == 0x01))
		return OR_FAIL;
	//hack, decrement ml to save place for '\0'
	--ml;
	int p = 0;
	bool is_found = false;
	int l, r;
	while(p < len)
	{
		if (inbuf[p] == '.')
		{
			//find left
			l = p;
			while ((l > 0) && idn(inbuf[l - 1])) --l;
			//find right
			r = p;
			while ((r < (len - 1)) && idn(inbuf[r + 1])) ++r;
			//check
			if (l < p && r > p && (r - l + 1) < ml)
			{
				is_found = true;
				break;
			}
		}
		++p;
	}
	if (!is_found) return OR_FAIL;
	#ifdef DEBUG_FIND_URL
		WaitForSingleObject(debug, INFINITE);
		printf("\n l(%d) r(%d) sb[l](%c) sb[r](%c) \n", l, r, inbuf[l], inbuf[r]);
		ReleaseMutex(debug);
	#endif
	for (int i = l; i <= r; ++i)
		url[i - l] = inbuf[i];
	url[ml] = 0;
	return OR_SUCCESS;
}

OperationResult findGET(const char* inbuf, int l, char *url, int ml)
{
	if (!(inbuf[0] == 'G' && inbuf[1] == 'E' && inbuf[2] == 'T'))
		return OR_FAIL;
	//hack, decrement ml to save place for '\0'
	--ml;
	int p = 0;
	bool is_found = false;
	while ((p + 5) < l)
	{
		if (inbuf[p] == 'H'
		 && inbuf[p + 1] == 'o'
		 && inbuf[p + 2] == 's'
		 && inbuf[p + 3] == 't'
		 && inbuf[p + 4] == ':'
		 && inbuf[p + 5] == ' '
		)
		{
			is_found = true;
			break;
		}
		++p;
	}
	if (!is_found) return OR_FAIL;
	p = p + 6;
	int pu = 0;
	while((p < l) && (pu < ml) && idn(inbuf[p]))//(inbuf[p] != 0x0d) && (inbuf[p] != 0x0a)
	{
		//if (!idn(inbuf[p])) return OR_FAIL;
		url[pu] = inbuf[p];
		++p;
		++pu;
	}
	url[ml] = 0;
	return OR_SUCCESS;
}

_Thread(connection_th)
{
	#ifdef DEBUG
		int id = 0;
		WaitForSingleObject(debug, INFINITE);
		printf("0x%04x:%03d\t New connect\n", pParam, ++id);
		ReleaseMutex(debug);
	#endif
	SOCKET s = (SOCKET)pParam;  //input socket
	SOCKET tunnelSock = 0;  //tunnel socket
	Stream *ss = new SocketStream(&s);  //input stream
	#ifdef DEBUG
		ss->val = pParam;
	#endif
	Stream *ts = new SocketStream(&tunnelSock);  //tunnel stream
	char buffer[300];  //buffer
	int lbuffer;  //real lenght data in buffer
	OperationResult r;  //variable for store result of read operations
	int waitResult;  //variable for store result of waiting socket
	
	//SOCKS5 structs
	SOCKS5_ClientGreeting cl_greeting;
	SOCKS5_ClientRequest cl_req;
	SOCKS5_ServerGreeting sr_greeting;
	SOCKS5_ServerResponse sr_rsp;
	
	//SOCKS4 structs
	SOCKS4_ClientRequest s4cl;
	SOCKS4_ServerResponse s4sr;
	
	try
	{
		////int iConnectResult = 0, iReceiveRes = 0, iSendRes = 0, iSocketsSet = 0;
		////SOCKS4_REQUEST socks4Request, socks4Response;
		////SOCKADDR_IN remoteAddr = {0};
		
		//check data in socket 's'
		fd_set fds_read;  //create socket set
		FD_ZERO(&fds_read);  //clear set
		FD_SET(s, &fds_read); //put socket 's' into set
		TIMEVAL tv = {0};  //create timeval for timelimit
		tv.tv_sec = 30;  //set timelimit to 30 secs
		
		{//wait data
			#ifdef DEBUG
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:%03d\t Wait client greeting...\n", pParam, ++id);
				ReleaseMutex(debug);
			#endif
			waitResult = select(0, &fds_read, NULL, NULL, &tv);
			#ifdef DEBUG
				WaitForSingleObject(debug, INFINITE);
				printf("0x%04x:%03d\t Waiting done with code 0x%x\n", pParam, ++id, waitResult);
				ReleaseMutex(debug);
			#endif
			if (waitResult == SOCKET_ERROR  //error ocurred
			  ||waitResult == 0)  //or timeout limit
				throw _LeaveException();
		}
		ioctlsocket(s, FIONBIO , &BLK); //blocking reading
		
		char vr;
		ss->view((char*)&vr, 1);
		if (vr == 5)
		{
			{//read client greeting
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Read client greeting...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				r = cl_greeting.read(ss);
				if (r == OR_FAIL) throw _LeaveException();
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Done reading client greeting, nMethods(%d) ", pParam, ++id, cl_greeting.nMethods);
					for (size_t i = 0; i < cl_greeting.nMethods; ++i)
					{
						printf("%02X ", cl_greeting.listMethods[i]);
					}
					printf("\n");
					ReleaseMutex(debug);
				#endif
			}
			{//check have no authentication method
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Check have no authentication method...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				int n = 0;
				for (; n < cl_greeting.nMethods && cl_greeting.listMethods[n] != 0x00; ++n);
				if (n >= cl_greeting.nMethods)
				{
					//send to client 'no required methods are available'
					sr_greeting.version = 0x05;
					sr_greeting.method = 0xff;
					//serialize and send
					sr_greeting.serialize(buffer);
					lbuffer = sr_greeting.serializedSize();
					r = ss->write(buffer, lbuffer);
					//leave connection
					throw _LeaveException();
				}
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Done checking have no authentication method\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
			}
			{//send server greeting
				//sr_greeting = SOCKS5_ServerGreeting();  //default greeting (no authentication)
				sr_greeting.init_default();
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Send server greeting %d %d...\n", pParam, ++id, sr_greeting.version, sr_greeting.method);
					ReleaseMutex(debug);
				#endif
				
				sr_greeting.serialize(buffer);  //serialize response
				lbuffer = sr_greeting.serializedSize();  //get size
				r = ss->write(buffer, lbuffer, 1);
				if (r == OR_FAIL) throw _LeaveException();
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Done sending server greeting\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
			}
			{//wait response from client
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Wait client request...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				waitResult = select(0, &fds_read, NULL, NULL, &tv);
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Waiting done with code 0x%x\n", pParam, ++id, waitResult);
					ReleaseMutex(debug);
				#endif
				if (waitResult == SOCKET_ERROR  //error ocurred
				  ||waitResult == 0)  //or timeout limit
					throw _LeaveException();
			}
			{//read client request
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Read client request...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				r = cl_req.read(ss);
				if (r == OR_FAIL) throw _LeaveException();
				#ifdef DEBUG
					{
						char bf[300];
						size_t l;
						cl_req.address.serialize(bf);
						l = cl_req.address.serializedSize();
						WaitForSingleObject(debug, INFINITE);
						printf("0x%04x:%03d\t Done reading client request ", pParam, ++id);
						for (size_t i = 0; i < l; ++i)
						{
							printf("%02X\t", (unsigned char)(bf[i]));
						}
						printf("\n");
						ReleaseMutex(debug);
					}
				#endif
				if (cl_req.address.atyp != SOCKS5_IPv4)
				{
					//send doesnt support address format 
					sr_rsp.version = 0x05;
					sr_rsp.report = REP_ATYP_NOT_SUPPORT;
					sr_rsp.address.set_ipv4_from_int(0);
					sr_rsp.serialize(buffer);
					lbuffer = sr_rsp.serializedSize();
					ss->write(buffer, lbuffer);
					#ifdef DEBUG
						WaitForSingleObject(debug, INFINITE);
						printf("0x%04x:%03d\t send doesnt support address format(%d)\n", pParam, ++id, cl_req.address.atyp);
						ReleaseMutex(debug);
					#endif
					throw _LeaveException();
				}
				if (cl_req.command != SOCKS5_CONNECT)
				{
					//send doesnt command support
					sr_rsp.version = 0x05;
					sr_rsp.report = REP_CMD_NOT_SUPPORT;
					sr_rsp.address.set_ipv4_from_int(0);
					sr_rsp.serialize(buffer);
					lbuffer = sr_rsp.serializedSize();
					ss->write(buffer, lbuffer);
					#ifdef DEBUG
						WaitForSingleObject(debug, INFINITE);
						printf("0x%04x:%03d\t send doesnt command support(%d)\n", pParam, ++id, cl_req.command);
						ReleaseMutex(debug);
					#endif
					throw _LeaveException();
				}
			}
			{//try tunnelSock create
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Try tunnelSock create...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				ioctlsocket(s, FIONBIO, &BLK);
				SOCKADDR_IN remoteAddr = {0};
				
				remoteAddr.sin_family = AF_INET;
				memcpy(&(remoteAddr.sin_addr),&(cl_req.address.ipv4[0]), sizeof(remoteAddr.sin_addr));
				remoteAddr.sin_port = cl_req.address.port;
				tunnelSock = socket(AF_INET, SOCK_STREAM, 0);
				int iConnectResult = connect(tunnelSock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr));
				if (iConnectResult == SOCKET_ERROR)
				{
					//send socks server error
					sr_rsp.version = 0x05;
					sr_rsp.report = REP_SERV_ERROR;
					sr_rsp.address.set_ipv4_from_int(0);
					sr_rsp.serialize(buffer);
					lbuffer = sr_rsp.serializedSize();
					ss->write(buffer, lbuffer);
					throw _LeaveException();
				}
				//send success
				sr_rsp.version = 0x05;
				sr_rsp.report = REP_SUCCESS;
				sr_rsp.address.set_ipv4_from_string(saddr);
				sr_rsp.address.port = port;
				sr_rsp.serialize(buffer);
				lbuffer = sr_rsp.serializedSize();
				r = ss->write(buffer, lbuffer);
				if (r == OR_FAIL) throw _LeaveException();
			}
		}
		else if (vr == 4)
		{
			//version 4
			{//read client request
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Read client request...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				r = s4cl.read(ss);
				if (r == OR_FAIL) throw _LeaveException();
				#ifdef DEBUG
					{
						WaitForSingleObject(debug, INFINITE);
						printf("0x%04x:%03d\t Done reading client request\n", pParam, ++id);
						ReleaseMutex(debug);
					}
				#endif
				if (s4cl.command != 0x01)
				{
					//send doesnt command support
					s4sr.command = 0x5b;//error
					s4sr.serialize(buffer);
					lbuffer = s4sr.serializedSize();
					ss->write(buffer, lbuffer);
					#ifdef DEBUG
						WaitForSingleObject(debug, INFINITE);
						printf("0x%04x:%03d\t send doesnt command support(%d)\n", pParam, ++id, s4cl.command);
						ReleaseMutex(debug);
					#endif
					throw _LeaveException();
				}
			}
			{//try tunnelSock create
				#ifdef DEBUG
					WaitForSingleObject(debug, INFINITE);
					printf("0x%04x:%03d\t Try tunnelSock create...\n", pParam, ++id);
					ReleaseMutex(debug);
				#endif
				ioctlsocket(s, FIONBIO, &BLK);
				SOCKADDR_IN remoteAddr = {0};
				
				remoteAddr.sin_family = AF_INET;
				memcpy(&(remoteAddr.sin_addr),&(s4cl.ipv4[0]), sizeof(remoteAddr.sin_addr));
				remoteAddr.sin_port = s4cl.port;
				tunnelSock = socket(AF_INET, SOCK_STREAM, 0);
				int iConnectResult = connect(tunnelSock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr));
				if (iConnectResult == SOCKET_ERROR)
				{
					//send socks server error
					s4sr.command = 0x5b;//error
					s4sr.serialize(buffer);
					lbuffer = s4sr.serializedSize();
					ss->write(buffer, lbuffer);
					throw _LeaveException();
				}
				//send success
				s4sr.command = 0x5a;//success
				s4sr.serialize(buffer);
				lbuffer = s4sr.serializedSize();
				r = ss->write(buffer, lbuffer);
				if (r == OR_FAIL) throw _LeaveException();
			}
		}
		else
		{
			throw _LeaveException();
		}
		//begin data transmission
		#ifdef DEBUG
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:%03d\t Begin data transmission...\n", pParam, ++id);
			ReleaseMutex(debug);
		#endif
		ioctlsocket(tunnelSock, FIONBIO, &BLK);
		ioctlsocket(s, FIONBIO, &BLK);
		const int lswapBuffer = 4096*16;
		char swapBuffer[lswapBuffer];
		int iSendResult, iRecvResult;
		tv.tv_sec = 2;
		while (true)
		{
			FD_ZERO(&fds_read);
			FD_SET(s, &fds_read);
			FD_SET(tunnelSock, &fds_read);
			int iSocketsSet = select(0, &fds_read, NULL, NULL, &tv);
			if (iSocketsSet > 0)
			{
				if (FD_ISSET(s, &fds_read))
				{
					iRecvResult = recv(s, swapBuffer, sizeof(swapBuffer), MSG_PEEK);
					if (iRecvResult == 0)
						throw _LeaveException();
					else
						iRecvResult = recv(s, swapBuffer, sizeof(swapBuffer), 0);
					
					if (iRecvResult != SOCKET_ERROR && iRecvResult > 0 )
					{
						const int lurl = 300;
						char url[lurl];
						OperationResult furl;
						furl = findGET(swapBuffer, iRecvResult, url, lurl);
						if (furl == OR_FAIL)
						{
							furl = find160301(swapBuffer, iRecvResult, url, lurl);
						}
						if (furl == OR_SUCCESS)
						{
							if (checkUrl(url) == OR_SUCCESS)
							{
								WaitForSingleObject(debug, INFINITE);
								printf("\x1b[32mpass:\t%s\x1b[0m\n", url);
								{//calc total statistic
									totall += iRecvResult;
									//trans byte to GB
									totalh += totall / 1073741824;
									totall %= 1073741824;
									++totalc;
								}
								{//print statistic
									printf("Statistic: %3d%%  %d/%d\n", (int)floor((blockc * 100.0) / totalc), blockc, totalc);
									printf("Total: %5d PB%5d TB%5d GB%5d MB%5d KB%5d B\n", totalh / 1048576, (totalh / 1024) % 1024, totalh % 1024, totall / 1048576, (totall / 1024) % 1024, totall % 1024);
									printf("Block: %5d PB%5d TB%5d GB%5d MB%5d KB%5d B\n", blockh / 1048576, (blockh / 1024) % 1024, blockh % 1024, blockl / 1048576, (blockl / 1024) % 1024, blockl % 1024);
								}
								ReleaseMutex(debug);
								iSendResult = send(tunnelSock, swapBuffer, iRecvResult, 0);
							}
							else
							{
								WaitForSingleObject(debug, INFINITE);
								printf("\x1b[31mblock:\t%s\x1b[0m\n", url);
								{//calc total statistic
									totall += iRecvResult;
									//trans byte to GB
									totalh += totall / 1073741824;
									totall %= 1073741824;
									++totalc;
								}
								{//calc total statistic
									blockl += iRecvResult;
									//trans byte to GB
									blockh += blockl / 1073741824;
									blockl %= 1073741824;
									++blockc;
								}
								{//print statistic
									printf("Statistic: %3d%%  %d/%d\n", (int)floor((blockc * 100.0) / totalc), blockc, totalc);
									printf("Total: %5d PB%5d TB%5d GB%5d MB%5d KB%5d B\n", totalh / 1048576, (totalh / 1024) % 1024, totalh % 1024, totall / 1048576, (totall / 1024) % 1024, totall % 1024);
									printf("Block: %5d PB%5d TB%5d GB%5d MB%5d KB%5d B\n", blockh / 1048576, (blockh / 1024) % 1024, blockh % 1024, blockl / 1048576, (blockl / 1024) % 1024, blockl % 1024);
								}
								ReleaseMutex(debug);
								//close connection
								throw _LeaveException();
								//#ifdef WRITE_BLOCK
								//	WaitForSingleObject(debug, INFINITE);
								//	printf("blocked: %s\n", url);
								//	ReleaseMutex(debug);
								//#endif
							}
						}
						else
						{
							iSendResult = send(tunnelSock, swapBuffer, iRecvResult, 0);
						}
						#ifdef DEBUG_TRANSMISSION
							{//write first 150 symbols
								WaitForSingleObject(debug, INFINITE);
								printf("0x%04x:%03d\t Transmission(%d)", pParam, ++id, iRecvResult);
								
								if (furl == OR_SUCCESS)
								{
									printf("\t\t \"%s\" \n", url);
								}
								else
								{
									printf("\n");
								}
								int l = iRecvResult;
								if (l > 150)
									l = 150;
								printf(">");
								for (int i = 0; i < l; ++i)
								{
									char s = swapBuffer[i];
									if (s >= '0' && s <= '9' || s >= 'a' && s <= 'z' || s >= 'A' && s <= 'Z')
										printf("\x1b[32m%c\x1b[0m", swapBuffer[i]);
									else
										printf(" %02X ", (unsigned char)(swapBuffer[i]));
								}
								printf("<\n");
								ReleaseMutex(debug);
							}
						#endif
						
					}
					else
						throw _LeaveException();
				}
				if (FD_ISSET(tunnelSock, &fds_read))
				{
					iRecvResult = recv(tunnelSock, swapBuffer, sizeof(swapBuffer), MSG_PEEK);
					if (iRecvResult == 0)
						throw _LeaveException();
					else
						iRecvResult = recv(tunnelSock, swapBuffer, sizeof(swapBuffer), 0);
					
					if (iRecvResult != SOCKET_ERROR && iRecvResult > 0 )
						iSendResult = send(s, swapBuffer, iRecvResult, 0);
					else
						throw _LeaveException();
				}
			}
		}
	}
	catch (const _LeaveException& e)
	{//-V565
		//just exit from thread
		#ifdef DEBUG
			WaitForSingleObject(debug, INFINITE);
			printf("0x%04x:%03d\t Leave one\n", pParam, ++id);
			//printf("Leave one.\n");
			ReleaseMutex(debug);
		#endif
	}
	if (s) closesocket(s);
	if (tunnelSock) closesocket(tunnelSock);
	return 0;
}

//hardcode
inline void init_hash(unsigned char (&hash)[5])
{
	hash[0] = 0xff;
	hash[1] = 0xff;
	hash[2] = 0xff;
	hash[3] = 0xff;
	hash[4] = 0xff;
}

//hardcode
inline void hash_step(int id, int mod8, unsigned char (&hash)[5])
{
	unsigned char mask = (1 << mod8);
	if (id & 0x01) hash[0] ^= mask;
	if (id & 0x02) hash[1] ^= mask;
	if (id & 0x04) hash[2] ^= mask;
	if (id & 0x08) hash[3] ^= mask;
	if (id & 0x10) hash[4] ^= mask;
}

OperationResult validateHeaderBin(FILE *furlsbin, binFileHeader *header)
{
	{//read header
		int iRead = fread(header, sizeof(binFileHeader), 1, furlsbin);
		if (iRead != 1) return OR_FAIL;//1 == number of readed elements
	}
	{//validate params
		//check ids
		if (memcmp(header->id, binID, 4) != 0) return OR_FAIL;
		//check countRecs
		if (header->countRecs > MAX_RECORDS) return OR_FAIL;
	}
	return OR_SUCCESS;
}

OperationResult calc_hash(unsigned char (&hash)[5], FILE *furlstxt)
{
	#ifdef DEBUG
		printf("calc_hash\n");
	#endif
	const int lurl = 300;
	char url[lurl];
	char sformat[40];
	sprintf(sformat, "%%%ds\0", lurl - 1);
	
	init_hash(hash);
	
	fscanf(furlstxt, sformat, url);
	int mod8 = 0;
	int nstring = 0;
	while(!feof(furlstxt))
	{
		++nstring;
		int len = strlen(url);
		for (int i = 0; i < len; ++i, mod8 = (mod8 + 1) % 8)
		{
			if (!idn(url[i]))
			{
				printf("<calc_hash>\t incorrect symbol str(%d) pos(%d)\n", nstring, i);
				return OR_FAIL;
			}
			hash_step(getIdByLetter(url[i]), mod8, hash);
		}
		fscanf(furlstxt, sformat, url);
	}
	return OR_SUCCESS;
}

OperationResult checkUrlsBin(FILE *furlstxt, FILE *furlsbin)
{
	#ifdef DEBUG
		printf("checkUrlsBin\n");
	#endif
	binFileHeader header;
	OperationResult r;
	r = validateHeaderBin(furlsbin, &header);
	if (r == OR_FAIL)
	{
		printf("<checkUrlsBin>\tincorrect header\n");
		return OR_FAIL;
	}
	unsigned char hash[5];
	r = calc_hash(hash, furlstxt);
	if (r == OR_FAIL)
	{
		printf("<checkUrlsBin>\tcant hash calc\n");
		return OR_FAIL;
	}
	if (memcmp(hash, header.hash, 5) != 0)
	{
		printf("<checkUrlsBin>\tdifferent hashes\n");
		return OR_FAIL;
	}
	return OR_SUCCESS;
}

OperationResult readCompiledList()
{
	#ifdef DEBUG
		printf("readCompiledList\n");
	#endif
	FILE *furlsbin;
	furlsbin = fopen("urls.bin", "rb");
	if (furlsbin == NULL)
	{//doesnt have compiled bin
		printf("<readCompiledList>\tdoesnt have urls.bin\n");
		return OR_FAIL;
	}
	binFileHeader header;
	OperationResult r;
	r = validateHeaderBin(furlsbin, &header);
	if (r == OR_FAIL)
	{
		printf("<readCompiledList>\tincorrect header urls.bin\n");
		fclose(furlsbin);
		return OR_FAIL;
	}
	records = new binRecord[header.countRecs];
	int iread = fread(records, sizeof(binRecord), header.countRecs, furlsbin);
	fclose(furlsbin);
	if (iread != header.countRecs)
	{
		printf("<readCompiledList>\tcant read records from urls.bin\n");
		return OR_FAIL;
	}
	return OR_SUCCESS;
}

void fill_bin_rec(binRecord *rec)
{
	#ifdef DEBUG
		printf("fill_bin_rec\n");
	#endif
	memset(rec, 0, sizeof(binRecord));
	rec->current = binP;
}

OperationResult doCompiledList()
{
	#ifdef DEBUG
		printf("doCompiledList\n");
	#endif
	FILE *furlstxt = fopen("urls.txt", "r");
	if (furlstxt == NULL)
	{//no urls.txt file
		printf("<doCompiledList>\tno urls.txt file\n");
		return OR_FAIL;
	}
	unsigned char hash[5];
	OperationResult r;
	r = calc_hash(hash, furlstxt);
	if (r == OR_FAIL)
	{
		printf("<doCompiledList>\tcant calc hash\n");
		return OR_FAIL;
	}
	fclose(furlstxt);
	int nstring = 0;
	int total_rec = 0;
	records = new binRecord[MAX_RECORDS];
	fill_bin_rec(&(records[total_rec++]));
	
	const int lurl = 300;
	char url[lurl];
	char sformat[40];
	sprintf(sformat, "%%%ds\0", lurl - 1);
	
	furlstxt = fopen("urls.txt", "r");
	fscanf(furlstxt, sformat, url);
	
	while (!feof(furlstxt))
	{
		reverse(url);
		++nstring;
		int len = strlen(url);
		int p = 0;
		for (int i = 0; i < len; ++i)
		{
			int id = getIdByLetter(url[i]);
			if (records[p].next[id] > 0)
			{
				p += records[p].next[id];
			}
			else
			{
				//printf("after rev\n");
				if (total_rec == MAX_RECORDS)
				{
					fclose(furlstxt);
					//nstring use
					printf("<doCompiledList>\tmax records(%d) limit str(%d) pos(%d)\n", MAX_RECORDS, nstring, i);
					delete[] records;
					return OR_FAIL;
				}
				else
				{
					fill_bin_rec(&(records[total_rec]));
					records[p].next[id] = total_rec - p;
					p = total_rec++;
				}
			}
		}
		records[p].current = binB;
		fscanf(furlstxt, sformat, url);
	}
	fclose(furlstxt);
	FILE *furlsbin;
	furlsbin = fopen("urls.bin", "wb");
	if (furlsbin == NULL)
	{
		printf("<doCompiledList>\tcant create urls.bin\n");
		delete[] records;
		return OR_FAIL;
	}
	binFileHeader header;
	memcpy(header.hash, hash, 5);
	memcpy(header.id, binID, 4);
	header.countRecs = total_rec;
	int iwrite = fwrite(&header, sizeof(binFileHeader), 1, furlsbin);
	if (iwrite != 1)//1 == number of written elements
	{
		printf("<doCompiledList>\tcant write header to urls.bin\n");
		fclose(furlsbin);
		delete[] records;
		return OR_FAIL;
	}
	printf("total_rec(%d)\n", total_rec);
	iwrite = fwrite(records, sizeof(binRecord), total_rec, furlsbin);
	fclose(furlsbin);
	delete[] records;
	if (iwrite != total_rec)//1 == number of written elements
	{
		printf("<doCompiledList>\tcant write records to urls.bin\n");
		return OR_FAIL;
	}
	return readCompiledList();
}

OperationResult doList()
{
	#ifdef DEBUG
		printf("doList\n");
	#endif
	FILE *furlstxt, *furlsbin;
	OperationResult r;
	furlsbin = fopen("urls.bin", "rb");
	if (furlsbin == NULL)
	{//doesnt have compiled bin
		printf("<doList>\tdoesnt have urls.bin, try make it...\n");
		return doCompiledList();
	}
	{//check bin file
		furlstxt = fopen("urls.txt", "r");
		if (furlstxt == NULL)
		{//no urls.txt file
			fclose(furlsbin);
			printf("<doList>\tno urls.txt file, try use unchecked urls.bin...\n");
			return readCompiledList();
		}
		r = checkUrlsBin(furlstxt, furlsbin);
		fclose(furlstxt);
		fclose(furlsbin);
	}
	if (r == OR_FAIL)
	{//urls.bin is deprecated
		printf("<doList>\turls.bin is deprecated, try recreate it...\n");
		return doCompiledList();
	}
	{//urls.bin is actual
		printf("<doList>\turls.bin is actual, try use it...\n");
		return readCompiledList();
	}
}

int main()
{
	//init statistic
	totalh = 0;
	totall = 0;
	totalc = 0;
	blockh = 0;
	blockl = 0;
	blockc = 0;
	//init list
	printf("<main>\tNeed 'nospam.exe' ('urls.txt' or/and 'urls.bin')\n");
	OperationResult r;
	r = doList();
	if (r == OR_FAIL)
	{
		printf("<main>\tMake list urls error.\n");
		return -1;
	}
	//#ifdef DEBUG
		//write statistic
	//#endif
	//return 0;
	debug = CreateMutex( 
	        NULL,              // default security attributes
	        FALSE,             // initially not owned
	        NULL);             // unnamed mutex
	if (debug == NULL) 
	{
		int lerr = GetLastError();
		printf("CreateMutex error: %d\n", lerr);
		return -1;
	}
	WSADATA wsa_data;
	int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (wsaResult != NO_ERROR)
	{
		printf("Error '%d' at WSAStartup()\n", wsaResult);
		return -1;
	}
	
	SOCKET listen_sock;
	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN addr_sock;
	addr_sock.sin_family = AF_INET;
	addr_sock.sin_addr.s_addr = htonl(addr);
	addr_sock.sin_port = htons(port);
	int bindResult = bind(listen_sock, (LPSOCKADDR)&addr_sock, sizeof(struct sockaddr));
	wsaResult = WSAGetLastError();
	if (bindResult)
	{
		printf("Error-1: Bind return %d\tdoes not bind on 127.0.0.1:%d\n", bindResult, port);
		switch (wsaResult)
		{
			case WSANOTINITIALISED:
				printf("WSANOTINITIALISED(%d)\n", WSANOTINITIALISED);
				printf("Note  A successful WSAStartup call must occur before using this function.\n");
				break;

			case WSAENETDOWN:
				printf("WSAENETDOWN(%d)\n", WSAENETDOWN);
				printf("The network subsystem has failed.\n");
				break;

			case WSAEACCES:
				printf("WSAEACCES(%d)\n", WSAEACCES);
				printf("An attempt was made to access a socket in a way forbidden by its access permissions.\n");
				printf("This error is returned if nn attempt to bind a datagram socket to the broadcast address failed because the setsockopt option SO_BROADCAST is not enabled.\n");
				break;

			case WSAEADDRINUSE:
				printf("WSAEADDRINUSE(%d)\n", WSAEADDRINUSE);
				printf("Only one usage of each socket address (protocol/network address/port) is normally permitted.\n");
				printf("This error is returned if a process on the computer is already bound to the same fully qualified address and the socket has not been marked to allow address reuse with SO_REUSEADDR. For example, the IP address and port specified in the name parameter are already bound to another socket being used by another application. For more information, see the SO_REUSEADDR socket option in the SOL_SOCKET Socket Options reference, Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE, and SO_EXCLUSIVEADDRUSE.\n");
				break;

			case WSAEADDRNOTAVAIL:
				printf("WSAEADDRNOTAVAIL(%d)\n", WSAEADDRNOTAVAIL);
				printf("The requested address is not valid in its context.\n");
				printf("This error is returned if the specified address pointed to by the name parameter is not a valid local IP address on this computer.\n");
				break;

			case WSAEFAULT:
				printf("WSAEFAULT(%d)\n", WSAEFAULT);
				printf("The system detected an invalid pointer address in attempting to use a pointer argument in a call.\n");
				printf("This error is returned if the name parameter is NULL, the name or namelen parameter is not a valid part of the user address space, the namelen parameter is too small, the name parameter contains an incorrect address format for the associated address family, or the first two bytes of the memory block specified by name do not match the address family associated with the socket descriptor s.\n");
				break;

			case WSAEINPROGRESS:
				printf("WSAEINPROGRESS(%d)\n", WSAEINPROGRESS);
				printf("A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function.\n");
				break;

			case WSAEINVAL:
				printf("WSAEINVAL(%d)\n", WSAEINVAL);
				printf("An invalid argument was supplied.\n");
				printf("This error is returned of the socket s is already bound to an address.\n");
				break;

			case WSAENOBUFS:
				printf("WSAENOBUFS(%d)\n", WSAENOBUFS);
				printf("An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.\n");
				printf("This error is returned of not enough buffers are available or there are too many connections.\n");
				break;

			case WSAENOTSOCK:
				printf("WSAENOTSOCK(%d)\n", WSAENOTSOCK);
				printf("An operation was attempted on something that is not a socket.\n");
				printf("This error is returned if the descriptor in the s parameter is not a socket.\n");
				break;

			default:
				printf("Unrecognized.\nsigned    %d\nunsigned  %u\nhex       %x\n", wsaResult, (unsigned int)wsaResult, wsaResult);
		}
		return -1;
	}
	if (listen(listen_sock, 100))
	{
		printf("Error-2:\tdoes not listen 127.0.0.1:%d\n", port);
		return -1;
	}
	printf("Success:\tproxy on 127.0.0.1:%d\n", port);
	while (true)
	{
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)connection_th, (LPVOID)accept(listen_sock, 0, 0), 0, NULL);//-V513
	}
	return 0;
}