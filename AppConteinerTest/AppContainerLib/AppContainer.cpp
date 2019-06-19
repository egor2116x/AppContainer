#include "AppContainer.h"

void AppContainer::SetParams(const std::wstring & exePath, const std::wstring & containerName, const std::wstring & containerDesc)
{
    m_ExePath = exePath;
    m_ContainerName = containerName;
    m_ContainerDesc = containerDesc;
}

HRESULT AppContainer::RunProcess()
{
    if (m_ExePath.empty() || 
        m_ContainerName.empty() ||
        m_ContainerDesc.empty())
    {
        return E_FAIL;
    }

    return RunProcessImpl();
}

HRESULT AppContainer::GrantAccess(const std::wstring & filePath, const std::wstring & containerName)
{
    if (filePath.empty() || containerName.empty())
    {
        return E_FAIL;
    }
    return GrantAccessImpl(filePath, containerName);
}

HRESULT AppContainer::GrantAccess(const std::wstring & filePath)
{
    if (filePath.empty() || m_ContainerName.empty())
    {
        return E_FAIL;
    }

    return GrantAccessImpl(filePath, m_ContainerName);
}

HRESULT AppContainer::DeleteContainer(const std::wstring & containerName)
{
    if (containerName.empty())
    {
        return E_FAIL;
    }

    return ::DeleteAppContainerProfile(containerName.c_str());
}

HRESULT AppContainer::DeleteContainer()
{
    return DeleteContainer(m_ContainerName);
}

HRESULT AppContainer::RunProcessImpl()
{
    PSID sid;
    STARTUPINFOEXW startupInfo = { 0 };
    LPWSTR stringSid = nullptr;
    bool success = false;
    SECURITY_CAPABILITIES SecurityCapabilities = { 0 };
    DWORD numCapabilities = 0;
 
    do
    {
        HRESULT result = ::CreateAppContainerProfile(m_ContainerName.c_str(), m_ContainerName.c_str(), m_ContainerDesc.c_str(), nullptr, 0, &sid);
        if (!SUCCEEDED(result))
        {
            if (HRESULT_CODE(result) == ERROR_ALREADY_EXISTS)
            {
                result = DeriveAppContainerSidFromAppContainerName(m_ContainerName.c_str(), &sid);
                if (!SUCCEEDED(result))
                {
                    std::wcout << L"Failed to get existing AppContainer name, error code: " << HRESULT_CODE(result) << std::endl;
                    break;
                }
            }
            else
            {
                std::wcout << L"Failed to create AppContainer, error code: " << HRESULT_CODE(result) << std::endl;
                break;
            }
        }

        std::wcout << L"[Container Info]" << std::endl;
        std::wcout << L"name: " << m_ContainerName << std::endl;
        std::wcout << L"description: " << m_ContainerDesc << std::endl;

        if (::ConvertSidToStringSidW(sid, &stringSid))
        {
            std::wcout << L"Sid: " << stringSid << std::endl;
        }

        if (!SetSecurityCapabilities(sid, &SecurityCapabilities, &numCapabilities))
        {
            std::wcout << L"Failed to set security capabilities, error code: " << GetLastError() << std::endl;
            break;
        }

        SIZE_T attributeSize = 0;
        startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXW);

        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
        startupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attributeSize);

        if (!::InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, &attributeSize))
        {
            std::wcout << L"InitializeProcThreadAttributeList() failed, error code: " << GetLastError() << std::endl;
            break;
        }

        if (!::UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, 
                                        &SecurityCapabilities, sizeof(SecurityCapabilities), nullptr, nullptr))
        {
            std::wcout << L"UpdateProcThreadAttribute() failed, error code: " << GetLastError() << std::endl;
            break;
        }

        PROCESS_INFORMATION process_info = { 0 };

        if (!::CreateProcessW(NULL, &m_ExePath[0], NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
            (LPSTARTUPINFOW)&startupInfo, &process_info))
        {
            std::wcout << L"Failed to create process " << m_ExePath << L", error code: " << GetLastError() << std::endl;
            break;
        }

        std::wcout << L"Successfully executed " << m_ExePath << L" in AppContainer" << std::endl;

        success = true;

    } while (false);

    if (startupInfo.lpAttributeList)
    {
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
    }

    if (SecurityCapabilities.Capabilities)
    {
        free(SecurityCapabilities.Capabilities);
    }

    if (sid)
    {
        FreeSid(sid);
    }

    if (stringSid)
    {
        LocalFree(stringSid);
    }

    return (success ? ERROR_SUCCESS : E_FAIL);
}

HRESULT AppContainer::GrantAccessImpl(const std::wstring & filePath, const std::wstring & containerName)
{
    PSID sid = nullptr;
    LPWSTR stringSid = nullptr;
    bool success = false;

    do
    {
        HRESULT result = ::DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &sid);
        if (!SUCCEEDED(result))
        {
            std::wcout << L"Failed to get existing AppContainer name, error code: " << HRESULT_CODE(result) << std::endl;
            break;
        }

        std::wcout << L"[Container Info]" << std::endl;
        std::wcout << L"name: " << containerName << std::endl;

        if (::ConvertSidToStringSidW(sid, &stringSid))
        {
            std::wcout << L"Sid: " << stringSid << std::endl;
        }


        if (!GrantNamedObjectAccess(sid, filePath.c_str(), SE_FILE_OBJECT, FILE_ALL_ACCESS))
        {
            std::wcout << L"Failed to grant explicit access to " << filePath << std::endl;

            break;
        }

        std::wcout << L"Successfully granted access to " << filePath << std::endl;
        success = true;
    } while (false);

    if (sid)
    {
        FreeSid(sid);
    }

    if (stringSid)
    {
        LocalFree(stringSid);
    }

    return success;
}

bool AppContainer::SetSecurityCapabilities(PSID containerSid, SECURITY_CAPABILITIES * capabilities, PDWORD numCapabilities)
{
    DWORD sid_size = SECURITY_MAX_SID_SIZE;
    size_t numCapabilities_ = appCapabilities.size();
    bool success = true;

    SID_AND_ATTRIBUTES * attributes = new SID_AND_ATTRIBUTES;

    ZeroMemory(capabilities, sizeof(SECURITY_CAPABILITIES));
    ZeroMemory(attributes, sizeof(SID_AND_ATTRIBUTES) * numCapabilities_);

    for (unsigned int i = 0; i < numCapabilities_; i++)
    {
        attributes[i].Sid = malloc(SECURITY_MAX_SID_SIZE);
        if (!::CreateWellKnownSid(appCapabilities[i], NULL, attributes[i].Sid, &sid_size))
        {
            success = false;
            break;
        }
        attributes[i].Attributes = SE_GROUP_ENABLED;
    }

    if (success == false)
    {
        for (unsigned int i = 0; i < numCapabilities_; i++)
        {
            if (attributes[i].Sid)
                ::LocalFree(attributes[i].Sid);
        }

        ::free(attributes);
        attributes = NULL;
        numCapabilities_ = 0;
    }

    capabilities->Capabilities = attributes;
    capabilities->CapabilityCount = numCapabilities_;
    capabilities->AppContainerSid = containerSid;
    *numCapabilities = numCapabilities_;

    return success;
}

bool AppContainer::IsProcessInContainer(HANDLE process)
{
    if (process == nullptr)
    {
        return false;
    }

    HANDLE processToken;
    int isContainer = 0;
    DWORD returnLength;

    if (!::OpenProcessToken(process, TOKEN_QUERY, &processToken))
    {
        return false;
    }

    if (!::GetTokenInformation(processToken, TokenIsAppContainer, &isContainer, sizeof(isContainer), &returnLength))
    {
        return false;
    }

    return isContainer != 0;
}

bool AppContainer::GrantNamedObjectAccess(PSID appContainerSid, const WCHAR * objectName, SE_OBJECT_TYPE objectType, DWORD accessMask)
{
    EXPLICIT_ACCESS_W explicitAccess;
    PACL originalAcl = nullptr;
    PACL newAcl       = nullptr;
    DWORD status;
    bool success = false;
    std::wstring localObjName = objectName;

    do
    {
        explicitAccess.grfAccessMode = GRANT_ACCESS;
        explicitAccess.grfAccessPermissions = accessMask;
        explicitAccess.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

        explicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        explicitAccess.Trustee.pMultipleTrustee = nullptr;
        explicitAccess.Trustee.ptstrName = reinterpret_cast<wchar_t *>(appContainerSid);
        explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

        status = ::GetNamedSecurityInfoW(objectName, objectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &originalAcl, nullptr, nullptr);

        if (status != ERROR_SUCCESS)
        {
            std::wcout << L"GetNamedSecurityInfoW failed for " << objectName << " error: " << status << std::endl;
            break;
        }

        status =::SetEntriesInAclW(1, &explicitAccess, originalAcl, &newAcl);
        if (status != ERROR_SUCCESS)
        {
            std::wcout << L"SetEntriesInAclW failed for " << objectName << " error: " << status << std::endl;
            break;
        }

        status = ::SetNamedSecurityInfoW(&localObjName[0], objectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr);
        if (status != ERROR_SUCCESS)
        {
            std::wcout << L"SetNamedSecurityInfoW failed for " << objectName << " error: " << status << std::endl;
            break;
        }

        success = true;

    } while (false);

    if (originalAcl)
    {
        ::LocalFree(originalAcl);
    }

    if (newAcl)
    {
        ::LocalFree(newAcl);
    }

    return success;
}
