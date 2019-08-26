#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string.h>
#include <Windows.h>
#include <fstream>
#include <tchar.h>
#include <wchar.h>
#include <stdio.h>
#include <cstddef>
#include "CuckooSandboxAgent.h"
#include <regex>

#include <curl/curl.h>
#include <json/json.h>
using namespace std;
#if defined(UNICODE) || defined(_UNICODE)
#define tcout std::wcout
#else
#define tcout std::cout
#endif
namespace
{
	std::size_t callback(
		const char* in,
		std::size_t size,
		std::size_t num,
		std::string* out)
	{
		const std::size_t totalBytes(size * num);
		out->append(in, totalBytes);
		return totalBytes;
	}
}


#define MAX_PATH_EX (MAX_PATH * 5)
const wchar_t* SAMPLE_PATH = L"E:\\sampletest";
TCHAR szDestDir[MAX_PATH] = L"C:\\Cuckoo Sandbox Analysis";
const char* URL_SUBMIT = "http://30.30.30.61:1337/tasks/create/file";
string URL_REPORT = "http://30.30.30.61:1337/tasks/report/";
string URL_VIEW = "http://30.30.30.61:1337/tasks/view/";
static const char AUTHORIZATION[] = "Authorization: Bearer van";


string szSTATUS[4] = {
	"Uploaded",
	"Analyzing",
	"Awaiting result"
};

//************************************************************************
// Method:    Find PE files in folder
// Access:    public 
// Parameter: szPath - Address of folder to add file
//************************************************************************
int FindFile(const wchar_t* lpszPath)
{
	WIN32_FIND_DATA FindFileData;
	TCHAR szFileName[MAX_PATH_EX];
	TCHAR szFullFileName[MAX_PATH_EX];
	TCHAR szSubDir[MAX_PATH_EX];
	HANDLE hFile;


	if (lpszPath == NULL) return 0;
	_tcscpy_s(szFileName, MAX_PATH_EX, lpszPath);
	_tcscat_s(szFileName, MAX_PATH_EX, L"\\*.*");

	hFile = FindFirstFile(szFileName, &FindFileData);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	do
	{
		if (_tcsicmp(FindFileData.cFileName, L".") == 0 || _tcsicmp(FindFileData.cFileName, L"..") == 0)
		{
			continue;
		}
		if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			_tcscpy_s(szSubDir, MAX_PATH_EX, lpszPath);
			_tcscat_s(szSubDir, MAX_PATH_EX, L"\\");
			_tcscat_s(szSubDir, MAX_PATH_EX, FindFileData.cFileName);
			FindFile(szSubDir);
		}
		else
		{
			_tcscpy_s(szFullFileName, MAX_PATH_EX, lpszPath);
			_tcscat_s(szFullFileName, MAX_PATH_EX, L"\\");
			_tcscat_s(szFullFileName, MAX_PATH_EX, FindFileData.cFileName);


			tcout << szFullFileName << endl;
			wstring szTemp(&szFullFileName[0]);
			string  szSampleFile(szTemp.begin(), szTemp.end());
			TaskSubmit(szSampleFile);

		}

	} while (FindNextFile(hFile, &FindFileData));
	FindClose(hFile);
	//return szFullFileName;
}

//************************************************************************
// Method:    Upload PE files in folder to Cuckoo Sandbox
// Access:    public 
// Parameter: sampleFile - 
//************************************************************************
void TaskSubmit(const std::string& sampleFile)
{
	CURL* curlSubmit = curl_easy_init();
	struct curl_slist* headerList = NULL;
	struct curl_httppost* formPost = NULL;
	struct curl_httppost* lastPtr = NULL;


	headerList = curl_slist_append(headerList, AUTHORIZATION);

	curl_formadd(&formPost, &lastPtr,
		CURLFORM_COPYNAME, "file",
		CURLFORM_FILE, sampleFile.c_str(),
		CURLFORM_END
	);

	if (curlSubmit)
	{
		curl_easy_setopt(curlSubmit, CURLOPT_URL, URL_SUBMIT);
		curl_easy_setopt(curlSubmit, CURLOPT_HTTPHEADER, headerList);
		curl_easy_setopt(curlSubmit, CURLOPT_HTTPPOST, formPost);
		cout << "\n******************************\n" << endl;
		cout << szSTATUS[0] << endl;

		int httpCodeSubmit(0);
		unique_ptr<std::string> httpDataSubmit(new std::string());

		curl_easy_setopt(curlSubmit, CURLOPT_WRITEFUNCTION, callback);
		curl_easy_setopt(curlSubmit, CURLOPT_WRITEDATA, httpDataSubmit.get());

		curl_easy_perform(curlSubmit);
		curl_easy_getinfo(curlSubmit, CURLINFO_RESPONSE_CODE, &httpCodeSubmit);

		if (httpCodeSubmit == 200)
		{
			Json::Value jsonDataSubmit;
			Json::Reader jsonReaderSubmit;

			if (jsonReaderSubmit.parse(*httpDataSubmit, jsonDataSubmit))
			{
				const std::string taskID(jsonDataSubmit["task_id"].asString());
				cout << "+ Task ID: " << taskID << endl;

				cout << szSTATUS[1] << endl;
				Sleep(300000);

				string URL_REPORT_ID = URL_REPORT + taskID;

				TaskReport((const char*)URL_REPORT_ID.c_str(), headerList);

			}
		}

	}

}

//************************************************************************
// Method:    
// Access:    public 
// Parameter:  
//************************************************************************
void TaskReport(const char* URL_REPORT_ID, struct curl_slist* header)
{
	CURL* curlReport = curl_easy_init();
	//struct curl_slist* headerList = NULL;

	header = curl_slist_append(header, AUTHORIZATION);


	if (curlReport)
	{
		curl_easy_setopt(curlReport, CURLOPT_URL, URL_REPORT_ID);
		curl_easy_setopt(curlReport, CURLOPT_HTTPHEADER, header);

		cout << "\n******************************\n" << endl;
		cout << szSTATUS[0] << endl;

		int httpCodeReport(0);
		unique_ptr<std::string> httpDataReport(new std::string());

		curl_easy_setopt(curlReport, CURLOPT_WRITEFUNCTION, callback);
		curl_easy_setopt(curlReport, CURLOPT_WRITEDATA, httpDataReport.get());

		curl_easy_perform(curlReport);
		curl_easy_getinfo(curlReport, CURLINFO_RESPONSE_CODE, &httpCodeReport);

		if (httpCodeReport == 200)
		{
			Json::Value jsonDataReport;
			Json::Reader jsonReaderReport;

			if (jsonReaderReport.parse(*httpDataReport, jsonDataReport))
			{
				auto szProcessTree = jsonDataReport["behavior"]["processtree"];
				auto szProcesses = jsonDataReport["behavior"]["processes"];
				auto szSignatures = jsonDataReport["signatures"];

				if (szProcessTree.size() >= 2) {
					//To do
					//char 
					for (int x = 0; x < szSignatures.size(); ++x) 
						for(int y = 0; y < 1000; ++y)
						{
							regex pattern("1baitfolder");
							const std::string checkFolder((szSignatures[x]["marks"][y]["ioc"]).asString());
							if (regex_match(checkFolder, pattern)) {
								cout << "co" << endl;
							}
							
						}

					for (int i = 0; i < szProcesses.size(); ++i)
						for (int j = 0; j < 40000; ++j)
						{
							cout << szSTATUS[2] << endl;
							if (szProcesses[i]["calls"][j]["arguments"]["string"] == "1baitfolder")
							{

							}
						}
				}
			}
		}

	}

}

int main(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
	CreateDirectoryW(szDestDir, NULL);
	FindFile(SAMPLE_PATH);
	return 0;
}