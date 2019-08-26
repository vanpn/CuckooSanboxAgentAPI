#pragma once
#include <tchar.h>

class CuckooSandboxAgentApp
{
public:
	void FindFile(TCHAR* szPath);


}; 
void TaskSubmit(const std::string& sampleFile);

void TaskReport(const char* URL_REPORT_ID, struct curl_slist* header);
