#define WIN32_LEAN_AND_MEAN 
#include <windows.h> 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") 
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <wincrypt.h>
#include<string.h>
#include <conio.h>
#pragma warning(disable : 4996)

#include <iostream>
#include <string>
#include <vector>
// #include <chrono> // for sleep
// #include <thread> // for sleep

#define MAX_COMMAND_SIZE 500
#define MAX_BUFFER_SIZE 2048
#define KEY_BUF_SIZE 256
#define MIN_PATH_SIZE 5
using namespace std;

typedef struct sock
{
	int s;

	HCRYPTPROV DescCSP;
	HCRYPTKEY DescKey;
	HCRYPTKEY DescKey_imp;
	HCRYPTKEY hPublicKey, hPrivateKey;

}socketExtended;

vector<socketExtended> sockets;

int init()
{
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}

void deinit()
{
	WSACleanup();
}

int sock_err(const char* function, int s)
{
	int err;
	err = WSAGetLastError();
	cout << function << ": socket error: " << err << endl;
	return -1;
}

void s_close(int s)
{
	closesocket(s);
}

int connect_100ms(int s, struct sockaddr_in addr)
{
	// 10 попыток подключения
	for (int rec = 0; rec < 10; rec++)
	{
		// пробуем подключиться к серверу
		if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0)
			return EXIT_SUCCESS;
		else
		{
			cout << (rec + 1) << " time failed to connect to server" << endl;
			//Sleep((DWORD)100);
			//std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
	return EXIT_FAILURE;
}

unsigned int strLength(char* mas, int startPos)
{
	int i = startPos;
	for (int j = startPos - 1; j >= 0; j--)
	{
		if (mas[j] != '\0') break;
		else i--;
	}

	return i;
}

int crytp_send(int choiceSize, char* buffer, unsigned int& bufSize, int s, char* choice)
{
	if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
		cout << "Error: " << GetLastError() << endl;

	if (send(sockets[s].s, choice, choiceSize, 0) < 0)
		return sock_err("send", sockets[s].s);
	if (recv(sockets[s].s, buffer, MAX_BUFFER_SIZE, 0) < 0)
		return sock_err("receive", sockets[s].s);

	bufSize = strLength(buffer, MAX_BUFFER_SIZE);
	if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)buffer, (DWORD*)&bufSize))
		cout << "Error: " << GetLastError() << endl;

	return EXIT_FAILURE;
}

int CryptReal(int s, sockaddr_in addr)
{
	socketExtended result;
	// для создания контейнера ключей с определенным CSP
	/*phProv – указатель на дескриптор CSP.
	  pszContainer – имя контейнера ключей.
	  pszProvider – имя CSP.
	  dwProvType – тип CSP.
	  dwFlags – флаги.*/
	  /*
	  Создает новый контейнер ключей с именем, указанным в pszContainer .\
	  Если pszContainer имеет значение NULL , создается контейнер ключей \
	  с именем по умолчанию.
	  */
	if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&result.DescCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			cout << "Error: " << GetLastError() << endl;
	}

	/*
	Данная функция предназначена для генерации сеансового ключа,
	а также для генерации пар ключей для обмена и цифровой подписи.
		hProv– дескриптор CSP.
		Algid – идентификатор алгоритма(указываем, что генерируем пару ключей, а не подпись).
		dwFlags – флаги.
		phKey – указатель на дескриптор ключа.*/
	if (CryptGenKey(result.DescCSP, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &result.DescKey) == 0)
		cout << "Error: " << GetLastError() << endl;

	//Функция CryptGetUserKey извлекает дескриптор одной из двух пар открытого и закрытого ключей пользователя
	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPublicKey))
		cout << "CryptGetUserKey error" << endl;
	if (!CryptGetUserKey(result.DescCSP, AT_KEYEXCHANGE, &result.hPrivateKey))
		cout << "CryptGetUserKey error" << endl;

	char ExpBuf[KEY_BUF_SIZE] = { 0 };
	DWORD len = KEY_BUF_SIZE;

	//Клиент посылает публичный ключ серверу
	//2й аргумент - 0, тк мы не шифруем посылаемый публичный ключ
	/*
	hKey – дескриптор экспортируемого ключа.
	hExpKey – ключ, с помощью которого будет зашифрован hKey при экспорте.
	dwBlobType – тип экспорта.
	dwFlags – флаги.
	pbData – буфер для экспорта. Будет содержать зашифрованный hKey с помощью
	hExpKey.
	pdwDataLen – длина буфера на вход. На выходе – количество значащих байт
	*/
	if (!CryptExportKey(result.hPublicKey, 0, PUBLICKEYBLOB, NULL, (BYTE*)ExpBuf, &len))
		cout << "Error: " << GetLastError() << endl;

	//передаём длину ключа
	int expBufSize = strLength(ExpBuf, KEY_BUF_SIZE);
	ExpBuf[expBufSize] = expBufSize;

	//отправка - получение информации
	if (send(s, ExpBuf, (expBufSize + 1), 0) < 0)
		sock_err("send", s);
	char buffer[KEY_BUF_SIZE] = { 0 };
	if (recv(s, buffer, KEY_BUF_SIZE, 0) < 0)
		sock_err("receive", s);

	int bufSize = strLength(buffer, KEY_BUF_SIZE) - 1;
	unsigned int dli = (unsigned char)buffer[bufSize];
	buffer[bufSize] = 0;

	//Клиент получает зашифрованное сообщение и расшифровывает его с помощью
	//своего приватного ключа
	//Функция предназначена для получения из каналов информации значения\
	ключа
	/*
	hProv – дескриптор CSP.
	pbData – импортируемый ключ представленный в виде массива байт.
	dwDataLen –длина данных в pbData.
	hPubKey - дескриптор ключа, который расшифрует ключ содержащийся в pbData.
	dwFlags - флаги.
	phKey – указатель на дескриптор ключа. Будет указывать на импортированный ключ
	*/
	if (!CryptImportKey(result.DescCSP, (BYTE*)buffer, dli, result.hPrivateKey, 0, &result.DescKey_imp))//получаем сеансовый ключ
		cout << "Error: " << GetLastError() << endl;
	result.s = s;
	sockets.push_back(result);

	return s;
}

void input_str(char* choiceStr, char* choice)
{
	char temp[MAX_COMMAND_SIZE];
	int i = 0;
	int indexM = -1;
	for (; i < strlen(choiceStr); i++)
	{
		if (choiceStr[i] == ' ')
		{
			indexM = i;
			break;
		}

		temp[i] = choiceStr[i];
		temp[i + 1] = '\0';
	}

	if (strcmp(temp, "help") == 0)
	{
		choice[0] = 'h';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "add_server") == 0)
	{
		choice[0] = 'a';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "os_info") == 0)
	{
		choice[0] = 'o';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "current_time") == 0)
	{
		choice[0] = 't';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "time_since_launch") == 0)
	{
		choice[0] = 'm';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "disks_info") == 0)
	{
		choice[0] = 'f';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "memory_info") == 0)
	{
		choice[0] = 's';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "close_client") == 0)
	{
		choice[0] = 'e';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "quit") == 0)
	{
		choice[0] = 'q';
		choice[1] = '\0';
		return;
	}
	if (strcmp(temp, "rights") == 0)
	{
		choice[0] = 'p';
		choice[1] = ' ';
	}
	if (strcmp(temp, "own") == 0)
	{
		choice[0] = 'r';
		choice[1] = ' ';
	}
	int j = 0;
	for (i = 2, j = indexM + 1; j < strlen(choiceStr); i++, j++)
	{
		choice[i] = choiceStr[j];
		choice[i + 1] = '\0';
	}
	return;
}

int addNewSocket()
{
	cout << "Enter ip and port (for example, 127.0.0.1:8080): ";

	string ipAddrAndPort = "";

	cin >> ipAddrAndPort;
	string ipAddress = ipAddrAndPort.substr(0, ipAddrAndPort.find(":"));
	string port = ipAddrAndPort.substr(ipAddrAndPort.find(":") + 1);

	if (port.size() == 0)
		return sock_err("finding the port", 0);

	int s;
	struct sockaddr_in addr;
	short num_port = (short)atoi(port.c_str());

	init(); // инициализация

	// создание сокета
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return sock_err("socket", s);

	// Заполнение структуры с адресом удаленного узла 
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(num_port);
	addr.sin_addr.s_addr = inet_addr(ipAddress.c_str());

	// попытка установить соединение (10 раз)
	if (connect_100ms(s, addr) != 0)
	{
		s_close(s);
		return sock_err("connect", s);
	}
	cout << "Socket connected successfully!" << endl;

	//crypt
	s = CryptReal(s, addr);

	cout << "Socket No: " << sockets.size() << endl;

	return s;
}


void PrintCommands()
{
	cout << "add_server - add connection to new server" << endl;
	cout << "os_info - information about OS (type and version)" << endl;
	cout << "current_time - current time in OS" << endl;
	cout << "time_since_launch - time since OS launched" << endl;
	cout << "disks_info - information about disks" << endl;
	cout << "memory_info - information about state of computer's memory" << endl;
	cout << "rights \'path\' - access rights in text form to the specified file/folder/registry key" << endl;
	cout << "own \'path\' - owner of the file/folder/registry key" << endl;
	cout << "close_client - close client connection" << endl;
	cout << "quit - exit program" << endl;
}


int io_serv()
{
	char buffer[MAX_BUFFER_SIZE] = { 0 };
	char choice[MAX_COMMAND_SIZE];
	char choiceStr[MAX_COMMAND_SIZE];
	char socketNumStr[MAX_COMMAND_SIZE];
	unsigned int choiceSize;
	unsigned int bufSize;
	bool start = true;
	int s = 0;


	do
	{
		memset(buffer, 0, MAX_BUFFER_SIZE);
		memset(choice, 0, MAX_COMMAND_SIZE);
		if (!start)
			cout << ">> ";
		else
		{
			int socket_res = addNewSocket();
			if (socket_res == -1)
			{
				cout << "Error connecting to server..." << endl;
				system("pause");
				return EXIT_FAILURE;
			}
			start = false;
			PrintCommands();
			cout << ">> ";
		}

		scanf("%d", &s);
		char sym;
		scanf("%c", &sym);
		if (s > 0)
		{
			s--;
			scanf("%[^\n]", choiceStr);
			input_str(choiceStr, choice);
			choiceSize = strlen(choice);
			switch (choice[0])
			{
			case 'o':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;

				cout << endl << buffer << endl;
				break;
			}
			case 't':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;
				cout << endl << buffer << endl;

				break;

			}
			case 'm':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;
				cout << endl << buffer << endl;
				break;
			}
			case 's':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;

				cout << endl << buffer << endl;
				break;
			}
			case 'f':
			{
				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;

				cout << endl << buffer << endl;
				break;
			}
			case 'p':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Invalid path..." << endl;
					break;
				}

				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;

				cout << buffer << endl;

				break;
			}
			case 'r':
			{
				if (choiceSize < MIN_PATH_SIZE)
				{
					cout << "Invalid path..." << endl;
					break;
				}

				if (crytp_send(choiceSize, buffer, bufSize, s, choice) == -1)
					return EXIT_FAILURE;

				cout << endl << buffer << endl;
				break;
			}
			case 'h':
			{
				PrintCommands();
				continue;
			}
			case 'a':
			{
				int socket_res = addNewSocket();
				if (socket_res == -1)
				{
					cout << "Error connecting to server..." << endl;
					//system("pause");
					//return EXIT_FAILURE;
					continue;
				}
				break;
			}
			case 'e':
			{
				if (!CryptEncrypt(sockets[s].DescKey_imp, 0, TRUE, 0, (BYTE*)choice, (DWORD*)&choiceSize, MAX_COMMAND_SIZE))
					cout << "Error: " << GetLastError() << endl;

				if (send(sockets[s].s, choice, strlen(choice), 0) < 0)
					return sock_err("send", sockets[s].s);

				if (!CryptDecrypt(sockets[s].DescKey_imp, NULL, TRUE, NULL, (BYTE*)choice, (DWORD*)&choiceSize))
					cout << "Error: " << GetLastError() << endl;
				break;
			}
			case 'q':
			{
				goto done;
			}
			default:
			{
				cout << "Incorrect command..." << endl;
				continue;
			}
			}
		}
		else
			cout << "specify socket number and try again!" << endl;

	} while (choice[0] != 'q');
done:
	cout << "Connection closed!" << endl;
	s_close(s);
	deinit();

	return EXIT_SUCCESS;
}

int main(void)
{
	setlocale(LC_ALL, "Russian");
	return io_serv();
}