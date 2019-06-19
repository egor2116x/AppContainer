#pragma once
#include "Common.h"

class AppContainer
{
public:
    AppContainer() {}
    AppContainer(const std::wstring & exePath, const std::wstring & containerName, const std::wstring & containerDesc) :
        m_ExePath(exePath), m_ContainerName(containerName), m_ContainerDesc(containerDesc) {}
    void SetParams(const std::wstring & exePath, const std::wstring & containerName, const std::wstring & containerDesc);
    HRESULT RunProcess();
    HRESULT GrantAccess(const std::wstring & filePath, const std::wstring & containerName);
    HRESULT GrantAccess(const std::wstring & filePath);
    HRESULT DeleteContainer(const std::wstring & containerName);
    HRESULT DeleteContainer();
private:
    HRESULT RunProcessImpl();
    HRESULT GrantAccessImpl(const std::wstring & filePath, const std::wstring & containerName);
    bool SetSecurityCapabilities(PSID containerSid, SECURITY_CAPABILITIES * capabilities, PDWORD numCapabilities);
    bool IsProcessInContainer(HANDLE process);
    bool GrantNamedObjectAccess(PSID appContainerSid, const WCHAR *objectName, SE_OBJECT_TYPE objectType, DWORD accessMask);
private:
    std::wstring m_ExePath;
    std::wstring m_ContainerName;
    std::wstring m_ContainerDesc;
};

