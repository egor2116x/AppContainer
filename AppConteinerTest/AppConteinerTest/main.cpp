#include <iostream>
#include <string>
#include <memory>
#include <sstream>
#include "AppContainer.h"

int wmain(int argc, wchar_t * argv[])
{
    if (argc < 2)
    {
        std::wcout << "Number params is wrong" << std::endl;
        std::cin.get();
        return 1;
    }

    const std::wstring command = argv[1];
    HRESULT result = E_FAIL;
    std::unique_ptr<AppContainer> container(new AppContainer);

    try
    {
        if (command.find(L"run") != std::wstring::npos && argc == 5) // <command> <processPath> <containerName> <containerDesc>
        {
            std::wstring exePath = argv[2];
            std::wstring containerName = argv[3];
            std::wstring containerDesc = argv[4];
            if (container != nullptr)
            {
                container->SetParams(exePath, containerName, containerDesc);
                result = container->RunProcess();
            }
        }
        else if (command.find(L"access") != std::wstring::npos && argc == 4) // <command> <containerName> <filePath>
        {
            std::wstring containerName = argv[2];
            std::wstring filePath = argv[3];
            if (container != nullptr)
            {
                result = container->GrantAccess(filePath, containerName);
            }
        }
        else if (command.find(L"delete") != std::wstring::npos && argc == 3) // <command> <containerName>
        {
            std::wstring containerName = argv[2];
            if (container != nullptr)
            {
                result = container->DeleteContainer(containerName);
            }
        }
        else if (command.find(L"info") != std::wstring::npos && argc == 2) // <command>
        {
            std::wcout << "Template <command> <Options>" << std::endl;
            std::wcout << "run <processPath> <containerName> <containerDesc>" << std::endl;
            std::wcout << "access <containerName> <filePath>" << std::endl;
            std::wcout << "delete <containerName>" << std::endl;
            std::wcout << "info" << std::endl;
        }
        else
        {
            std::wcout << "Number params is wrong" << std::endl;
            std::cin.get();
            return 1;
        }
    }
    catch (const std::runtime_error & e)
    {
        std::cout << "Exception is occured: " << e.what() << std::endl;
    }
    
    if (!SUCCEEDED(result))
    {
        std::wcerr << L"Error = " << HRESULT_CODE(result) << std::endl;
        std::cin.get();
        return 1;
    }
    
    std::cin.get();
    return 0;
}