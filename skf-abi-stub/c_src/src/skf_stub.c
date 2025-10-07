/*
 * skf_stub.c - C ABI Stub/Mock implementation for all SKF functions.
 * Purpose: Ensure Rust FFI bindings match the provided ABI (calling convention, struct layout).
 * * NOTE: This stub assumes 'sgd.h' defines types like ULONG, BYTE, CHAR, 
 * and constants like MAX_RSA_MODULUS_LEN, etc.
 */

#include "skf.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// --- 定义用于 ABI 验证的魔术值 ---

#define MOCK_DEV_HANDLE_VALUE 0xF1111111
#define MOCK_APP_HANDLE_VALUE 0xF2222222
#define MOCK_CONTAINER_HANDLE_VALUE 0xF3333333
#define MOCK_KEY_HANDLE_VALUE 0xF4444444
#define MOCK_HASH_KEY_HANDLE_VALUE 0xF5555555
#define MOCK_AGREEMENT_KEY_HANDLE_VALUE 0xF6666666
#define MOCK_MAC_KEY_HANDLE_VALUE 0xF8888888

#define MAX_ECC_CIPHER_LEN           20480
#define MOCK_ECC_CIPHER_LEN          32
#define MOCK_ECC_TOTAL_SIZE          (sizeof(ECCCIPHERBLOB) - 1 + MOCK_ECC_CIPHER_LEN)

#define EVENT_PLUGGED_IN 1
#define EVENT_UNPLUGGED 2


const char mock_dev_name[] = "DEV_10001\0";

const char mock_dev_list[] = "DEV_10001\0DEV_10002\0\0";

const char mock_app_list[] = "APP_T001\0APP_T002\0\0";

const char mock_container_list[] = "CON_T001\0CON_T002\0\0";

const char mock_file_list[] = "FILE_T001\0FILE_T002\0\0";

#define CHECK_NOT_NULL(ptr) \
    if ((ptr) == NULL) { return SAR_INVALIDPARAMERR; }

ULONG CheckEccCipherBlobValidity(PECCCIPHERBLOB pCipherBlob) {
    if (pCipherBlob == NULL) {
        printf("CheckEccCipherBlobValidity: Input structure pointer is NULL.\n");
        return SAR_INVALIDPARAMERR;
    }

    if (pCipherBlob->CipherLen == 0) {
        printf("CheckEccCipherBlobValidity: CipherLen is 0, which is likely invalid.\n");
        return SAR_INVALIDPARAMERR;
    }

    if (pCipherBlob->CipherLen > MAX_ECC_CIPHER_LEN) {
        printf("CheckEccCipherBlobValidity: CipherLen (%lu) exceeds max reasonable length.\n", pCipherBlob->CipherLen);
        return SAR_INVALIDPARAMERR;
    }

    for (ULONG i = 0; i < pCipherBlob->CipherLen; i++) {
        BYTE b = pCipherBlob->Cipher[i];
    }

    printf("CheckEccCipherBlobValidity: CipherLen is valid (%lu). Returning SAR_OK.\n", pCipherBlob->CipherLen);

    return SAR_OK;
}

void InitEccCipherBlob(PECCCIPHERBLOB pCipherBlob, ULONG cipherLen) {
    memset(pCipherBlob->XCoordinate, 0x1, sizeof(pCipherBlob->XCoordinate));
    memset(pCipherBlob->YCoordinate, 0x2, sizeof(pCipherBlob->YCoordinate));
    memset(pCipherBlob->HASH, 0x3, sizeof(pCipherBlob->HASH));

    pCipherBlob->CipherLen = cipherLen;

    memset(pCipherBlob->Cipher, 0x4, cipherLen);
}

/* 7.1.2 SKF_WaitForDevEvent */
ULONG DEVAPI SKF_WaitForDevEvent(
    LPSTR szDevName,
    ULONG *pulDevNameLen,
    ULONG *pulEvent) {
    CHECK_NOT_NULL(pulDevNameLen);
    CHECK_NOT_NULL(pulEvent);
    // 假设 1 是设备插入
    *pulEvent = EVENT_PLUGGED_IN;

    ULONG required_size = sizeof(mock_dev_name);
    if (szDevName == NULL || *pulDevNameLen == 0) {
        // 模拟第一次调用：获取所需缓冲区大小
        *pulDevNameLen = required_size;
        return SAR_BUFFER_TOO_SMALL;
    }

    // 写入魔术设备名
    if (*pulDevNameLen >= required_size) {
        strcpy(szDevName, mock_dev_name);
        *pulDevNameLen = strlen(mock_dev_name) + 1;
        return SAR_OK;
    }

    return SAR_FAIL; // 模拟失败
}

/* 7.1.3 SKF_CancelWaitForDevEvent */
ULONG DEVAPI SKF_CancelWaitForDevEvent(
    void) {
    // 总是成功
    return SAR_OK;
}

/* 7.1.4 SKF_EnumDev */
ULONG DEVAPI SKF_EnumDev(
    BOOL bPresent,
    LPSTR szNameList,
    ULONG *pulSize) {
    CHECK_NOT_NULL(pulSize);

    ULONG required_size = sizeof(mock_dev_list);

    if (szNameList == NULL || *pulSize < required_size) {
        // 返回需要的buffer大小
        *pulSize = required_size;
        return SAR_OK;
    }

    memcpy(szNameList, mock_dev_list, required_size);
    *pulSize = required_size;
    return SAR_OK;
}

/* 7.1.5 SKF_ConnectDev */
ULONG DEVAPI SKF_ConnectDev(
    LPSTR szName,
    DEVHANDLE *phDev) {
    CHECK_NOT_NULL(phDev);
    if (szName == NULL || strlen(szName) == 0) { return SAR_INVALIDPARAMERR; }

    *phDev = (DEVHANDLE) MOCK_DEV_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.1.6 SKF_DisConnectDev */
ULONG DEVAPI SKF_DisConnectDev(
    DEVHANDLE hDev) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.1.7 SKF_GetDevState */
ULONG DEVAPI SKF_GetDevState(
    LPSTR szDevName,
    ULONG *pulDevState) {
    CHECK_NOT_NULL(pulDevState);
    if (szDevName == NULL || strlen(szDevName) == 0) { return SAR_INVALIDPARAMERR; }

    // 模拟设备存在且正常
    *pulDevState = 1; // 假设 1 是设备存在
    return SAR_OK;
}

/* 7.1.8 SKF_SetLabel */
ULONG DEVAPI SKF_SetLabel(
    DEVHANDLE hDev,
    LPSTR szLabel) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szLabel == NULL || strlen(szLabel) == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.1.9 SKF_GetDevInfo */
ULONG DEVAPI SKF_GetDevInfo(
    DEVHANDLE hDev,
    DEVINFO *pDevInfo) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pDevInfo);

    // 写入魔术 DEVINFO 值供 ABI 验证
    memset(pDevInfo, 0, sizeof(DEVINFO));
    pDevInfo->Version.major = 0x01;
    pDevInfo->Version.minor = 0x02;
    pDevInfo->TotalSpace = 0xABCDEF00;
    strncpy(pDevInfo->Label, mock_dev_name, sizeof(pDevInfo->Label) - 1);

    return SAR_OK;
}

/* 7.1.10 SKF_LockDev */
ULONG DEVAPI SKF_LockDev(
    DEVHANDLE hDev,
    ULONG ulTimeOut) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.1.11 SKF_UnlockDev */
ULONG DEVAPI SKF_UnlockDev(
    DEVHANDLE hDev) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.1.12 SKF_Transmit */
ULONG DEVAPI SKF_Transmit(
    DEVHANDLE hDev,
    BYTE *pbCommand,
    ULONG ulCommandLen,
    BYTE *pbData,
    ULONG *pulDataLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulDataLen);

    // 模拟写入 16 字节数据
    ULONG required_len = 16;

    if (pbData == NULL || *pulDataLen < required_len) {
        *pulDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    // 写入魔术数据
    memset(pbData, 0xCC, required_len);
    *pulDataLen = required_len;

    return SAR_OK;
}

/* 7.2.2 SKF_ChangeDevAuthKey */
ULONG DEVAPI SKF_ChangeDevAuthKey(
    DEVHANDLE hDev,
    BYTE *pbKeyValue,
    ULONG ulKeyLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbKeyValue == NULL || ulKeyLen == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.2.3 SKF_DevAuth */
ULONG DEVAPI SKF_DevAuth(
    DEVHANDLE hDev,
    BYTE *pbAuthData,
    ULONG ulLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbAuthData == NULL || ulLen == 0) { return SAR_INVALIDPARAMERR; }
    // 模拟认证成功
    return SAR_OK;
}

/* 7.2.4 SKF_ChangePIN */
ULONG DEVAPI SKF_ChangePIN(
    HAPPLICATION hApplication,
    ULONG ulPINType,
    LPSTR szOldPin,
    LPSTR szNewPin,
    ULONG *pulRetryCount) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulRetryCount);
    if (szOldPin == NULL || szNewPin == NULL || ulPINType == 0) { return SAR_INVALIDPARAMERR; }

    // 假设 PIN 正确，模拟修改成功
    *pulRetryCount = 5;
    return SAR_OK;
}

/* 7.2.5 SKF_GetPINInfo */
LONG DEVAPI SKF_GetPINInfo(
    HAPPLICATION hApplication,
    ULONG ulPINType,
    ULONG *pulMaxRetryCount,
    ULONG *pulRemainRetryCount,
    BOOL *pbDefaultPin) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulMaxRetryCount);
    CHECK_NOT_NULL(pulRemainRetryCount);
    CHECK_NOT_NULL(pbDefaultPin);

    *pulMaxRetryCount = 5;
    *pulRemainRetryCount = 3; // 模拟剩余次数
    *pbDefaultPin = FALSE;
    return SAR_OK;
}

/* 7.2.6 SKF_VerifyPIN */
ULONG DEVAPI SKF_VerifyPIN(
    HAPPLICATION hApplication,
    ULONG ulPINType,
    LPSTR szPIN,
    ULONG *pulRetryCount) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulRetryCount);
    if (szPIN == NULL || ulPINType == 0) { return SAR_INVALIDPARAMERR; }

    if (strcmp(szPIN, "123456") == 0) {
        // 模拟 PIN 正确
        *pulRetryCount = 0; // 0 表示已登录/验证成功
        return SAR_OK;
    } else {
        // 模拟 PIN 错误
        *pulRetryCount = 2; // 模拟剩余 2 次
        return SAR_PIN_INCORRECT;
    }
}

/* 7.2.7 SKF_UnblockPIN */
ULONG DEVAPI SKF_UnblockPIN(
    HAPPLICATION hApplication,
    LPSTR szAdminPIN,
    LPSTR szNewUserPIN,
    ULONG *pulRetryCount) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulRetryCount);
    if (szAdminPIN == NULL || szNewUserPIN == NULL) { return SAR_INVALIDPARAMERR; }

    *pulRetryCount = 5;
    return SAR_OK;
}

/* 7.2.8 SKF_ClearSecureState */
ULONG DEVAPI SKF_ClearSecureState(
    HAPPLICATION hApplication) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.3.2 SKF_CreateApplication */
ULONG DEVAPI SKF_CreateApplication(
    DEVHANDLE hDev,
    LPSTR szAppName,
    LPSTR szAdminPin,
    DWORD dwAdminPinRetryCount,
    LPSTR szUserPin,
    DWORD dwUserPinRetryCount,
    DWORD dwCreateFileRights,
    HAPPLICATION *phApplication) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phApplication);
    if (szAppName == NULL || szAdminPin == NULL || szUserPin == NULL) { return SAR_INVALIDPARAMERR; }

    *phApplication = (HAPPLICATION) MOCK_APP_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.3.3 SKF_EnumApplication */
ULONG DEVAPI SKF_EnumApplication(
    DEVHANDLE hDev,
    LPSTR szAppName,
    ULONG *pulSize) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulSize);

    ULONG required_size = sizeof(mock_app_list);

    if (szAppName == NULL || *pulSize < required_size) {
        *pulSize = required_size;
        return SAR_BUFFER_TOO_SMALL;
    }

    memcpy(szAppName, mock_app_list, required_size);
    *pulSize = required_size;
    return SAR_OK;
}

/* 7.3.4 SKF_DeleteApplication */
ULONG DEVAPI SKF_DeleteApplication(
    DEVHANDLE hDev,
    LPSTR szAppName) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szAppName == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.3.5 SKF_OpenApplication */
ULONG DEVAPI SKF_OpenApplication(
    DEVHANDLE hDev,
    LPSTR szAppName,
    HAPPLICATION *phApplication) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phApplication);
    if (szAppName == NULL) { return SAR_INVALIDPARAMERR; }

    *phApplication = (HAPPLICATION) MOCK_APP_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.3.6 SKF_CloseApplication */
ULONG DEVAPI SKF_CloseApplication(
    HAPPLICATION hApplication) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.4.2 SKF_CreateFile */
ULONG DEVAPI SKF_CreateFile(
    HAPPLICATION hApplication,
    LPSTR szFileName,
    ULONG ulFileSize,
    ULONG ulReadRights,
    ULONG ulWriteRights) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szFileName == NULL || ulFileSize == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.4.3 SKF_DeleteFile */
ULONG DEVAPI SKF_DeleteFile(
    HAPPLICATION hApplication,
    LPSTR szFileName) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szFileName == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.4.4 SKF_EnumFiles */
ULONG DEVAPI SKF_EnumFiles(
    HAPPLICATION hApplication,
    LPSTR szFileList,
    ULONG *pulSize) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulSize);

    ULONG required_size = sizeof(mock_file_list);

    if (szFileList == NULL || *pulSize < required_size) {
        *pulSize = required_size;
        return SAR_BUFFER_TOO_SMALL;
    }

    memcpy(szFileList, mock_file_list, required_size);
    *pulSize = required_size;
    return SAR_OK;
}

/* 7.4.5 SKF_GetFileInfo */
ULONG DEVAPI SKF_GetFileInfo(
    HAPPLICATION hApplication,
    LPSTR szFileName,
    FILEATTRIBUTE *pFileInfo) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pFileInfo);
    if (szFileName == NULL) { return SAR_INVALIDPARAMERR; }

    // 写入魔术文件信息
    memset(pFileInfo, 0, sizeof(FILEATTRIBUTE));
    strncpy(pFileInfo->FileName, szFileName, sizeof(pFileInfo->FileName) - 1);
    pFileInfo->FileSize = 1024;
    pFileInfo->ReadRights = 1;
    return SAR_OK;
}

/* 7.4.6 SKF_ReadFile */
ULONG DEVAPI SKF_ReadFile(
    HAPPLICATION hApplication,
    LPSTR szFileName,
    ULONG ulOffset,
    ULONG ulSize,
    BYTE *pbOutData,
    ULONG *pulOutLen) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulOutLen);
    if (szFileName == NULL || ulSize == 0) { return SAR_INVALIDPARAMERR; }

    if (pbOutData == NULL || *pulOutLen < ulSize) {
        *pulOutLen = ulSize;
        return SAR_BUFFER_TOO_SMALL;
    }

    // 写入魔术数据
    memset(pbOutData, 0xDD, ulSize);
    *pulOutLen = ulSize;
    return SAR_OK;
}

/* 7.4.7 SKF_WriteFile */
ULONG DEVAPI SKF_WriteFile(
    HAPPLICATION hApplication,
    LPSTR szFileName,
    ULONG ulOffset,
    BYTE *pbData,
    ULONG ulSize) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szFileName == NULL || pbData == NULL || ulSize == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.5.2 SKF_CreateContainer */
ULONG DEVAPI SKF_CreateContainer(
    HAPPLICATION hApplication,
    LPSTR szContainerName,
    HCONTAINER *phContainer) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phContainer);
    if (szContainerName == NULL) { return SAR_INVALIDPARAMERR; }

    *phContainer = (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.5.3 SKF_DeleteContainer */
ULONG DEVAPI SKF_DeleteContainer(
    HAPPLICATION hApplication,
    LPSTR szContainerName) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (szContainerName == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.5.4 SKF_OpenContainer */
ULONG DEVAPI SKF_OpenContainer(
    HAPPLICATION hApplication,
    LPSTR szContainerName,
    HCONTAINER *phContainer) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phContainer);
    if (szContainerName == NULL) { return SAR_INVALIDPARAMERR; }

    *phContainer = (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.5.5 SKF_CloseContainer */
ULONG DEVAPI SKF_CloseContainer(
    HCONTAINER hContainer) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.5.6 SKF_EnumContainer */
ULONG DEVAPI SKF_EnumContainer(
    HAPPLICATION hApplication,
    LPSTR szContainerName,
    ULONG *pulSize) {
    if (hApplication != (HAPPLICATION) MOCK_APP_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulSize);

    ULONG required_size = sizeof(mock_container_list);

    if (szContainerName == NULL || *pulSize < required_size) {
        *pulSize = required_size;
        return SAR_BUFFER_TOO_SMALL;
    }

    memcpy(szContainerName, mock_container_list, required_size);
    *pulSize = required_size;
    return SAR_OK;
}

/* 7.5.7 SKF_GetContainerType */
ULONG DEVAPI SKF_GetContainerType(
    HCONTAINER hContainer,
    ULONG *pulContainerType) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulContainerType);

    *pulContainerType = 1; // 1: RSA
    return SAR_OK;
}

/* 7.5.8 SKF_ImportCertificate */
ULONG DEVAPI SKF_ImportCertificate(
    HCONTAINER hContainer,
    BOOL bExportSignKey,
    BYTE *pbCert,
    ULONG ulCertLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbCert == NULL || ulCertLen == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.5.9 SKF_ExportCertificate */
ULONG DEVAPI SKF_ExportCertificate(
    HCONTAINER hContainer,
    BOOL bSignFlag,
    BYTE *pbCert,
    ULONG *pulCertLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulCertLen);

    ULONG required_len = 512;

    if (pbCert == NULL || *pulCertLen < required_len) {
        *pulCertLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbCert, 0xEE, required_len);
    *pulCertLen = required_len;
    return SAR_OK;
}

/* 7.6.2 SKF_GenRandom */
ULONG DEVAPI SKF_GenRandom(
    DEVHANDLE hDev,
    BYTE *pbRandom,
    ULONG ulRandomLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbRandom == NULL || ulRandomLen == 0) { return SAR_INVALIDPARAMERR; }

    // 写入魔术随机数
    memset(pbRandom, 0xFF, ulRandomLen);
    return SAR_OK;
}

/* 7.6.3 SKF_GenExtRSAKey */
ULONG DEVAPI SKF_GenExtRSAKey(
    DEVHANDLE hDev,
    ULONG ulBitsLen,
    RSAPRIVATEKEYBLOB *pBlob) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pBlob);
    if (ulBitsLen == 0) { return SAR_INVALIDPARAMERR; }

    // 写入魔术私钥数据
    memset(pBlob, 0x1A, sizeof(RSAPRIVATEKEYBLOB));
    pBlob->AlgID = 1;
    return SAR_OK;
}

/* 7.6.4 SKF_GenRSAKeyPair */
ULONG DEVAPI SKF_GenRSAKeyPair(
    HCONTAINER hContainer,
    ULONG ulBitsLen,
    RSAPUBLICKEYBLOB *pBlob) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pBlob);
    if (ulBitsLen == 0) { return SAR_INVALIDPARAMERR; }

    memset(pBlob, 0x2B, sizeof(RSAPUBLICKEYBLOB));
    pBlob->AlgID = 1;
    return SAR_OK;
}

/* 7.6.5 SKF_ImportRSAKeyPair */
ULONG DEVAPI SKF_ImportRSAKeyPair(
    HCONTAINER hContainer,
    ULONG ulSymAlgId,
    BYTE *pbWrappedKey,
    ULONG ulWrappedKeyLen,
    BYTE *pbEncryptedData,
    ULONG ulEncryptedDataLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbWrappedKey == NULL || pbEncryptedData == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.6 SKF_RSASignData */
ULONG DEVAPI SKF_RSASignData(
    HCONTAINER hContainer,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbSignature,
    ULONG *pulSignLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulSignLen);
    if (pbData == NULL || ulDataLen == 0) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 256; // 假设 2048-bit key

    if (pbSignature == NULL || *pulSignLen < required_len) {
        *pulSignLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbSignature, 0x3C, required_len);
    *pulSignLen = required_len;
    return SAR_OK;
}

/* 7.6.7 SKF_RSAVerify */
ULONG DEVAPI SKF_RSAVerify(
    DEVHANDLE hDev,
    RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbSignature,
    ULONG ulSignLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pRSAPubKeyBlob == NULL || pbData == NULL || pbSignature == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK; // 模拟验证成功
}

/* 7.6.8 SKF_RSAExportSessionKey */
ULONG DEVAPI SKF_RSAExportSessionKey(
    HCONTAINER hContainer,
    ULONG ulAlgId,
    RSAPUBLICKEYBLOB *pPubKey,
    BYTE *pbData,
    ULONG *pulDataLen,
    HANDLE *phSessionKey) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulDataLen);
    CHECK_NOT_NULL(phSessionKey);
    if (pPubKey == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 256;
    if (pbData == NULL || *pulDataLen < required_len) {
        *pulDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbData, 0x4D, required_len);
    *pulDataLen = required_len;
    *phSessionKey = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.9 SKF_ExtRSAPubKeyOperation */
ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
    DEVHANDLE hDev,
    RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
    BYTE *pbInput,
    ULONG ulInputLen,
    BYTE *pbOutput,
    ULONG *pulOutputLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulOutputLen);
    if (pRSAPubKeyBlob == NULL || pbInput == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 256;
    if (pbOutput == NULL || *pulOutputLen < required_len) {
        *pulOutputLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbOutput, 0x5E, required_len);
    *pulOutputLen = required_len;
    return SAR_OK;
}

/* 7.6.10 SKF_ExtRSAPriKeyOperation */
ULONG DEVAPI SKF_ExtRSAPriKeyOperation(
    DEVHANDLE hDev,
    RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
    BYTE *pbInput,
    ULONG ulInputLen,
    BYTE *pbOutput,
    ULONG *pulOutputLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulOutputLen);
    if (pRSAPriKeyBlob == NULL || pbInput == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 256;
    if (pbOutput == NULL || *pulOutputLen < required_len) {
        *pulOutputLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbOutput, 0x6F, required_len);
    *pulOutputLen = required_len;
    return SAR_OK;
}

/* 7.6.11 SKF_GenECCKeyPair */
ULONG DEVAPI SKF_GenECCKeyPair(
    HCONTAINER hContainer,
    ULONG ulAlgId,
    ECCPUBLICKEYBLOB *pBlob) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pBlob);
    if (ulAlgId == 0) { return SAR_INVALIDPARAMERR; }

    memset(pBlob, 0x7A, sizeof(ECCPUBLICKEYBLOB));
    return SAR_OK;
}

/* 7.6.12 SKF_ImportECCKeyPair */
ULONG DEVAPI SKF_ImportECCKeyPair(
    HCONTAINER hContainer,
    ENVELOPEDKEYBLOB *pEnvelopedKeyBlob) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pEnvelopedKeyBlob == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.13 SKF_ECCSignData */
ULONG DEVAPI SKF_ECCSignData(
    HCONTAINER hContainer,
    BYTE *pbDigest,
    ULONG ulDigestLen,
    ECCSIGNATUREBLOB *pSignature) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pSignature);
    if (pbDigest == NULL || ulDigestLen == 0) { return SAR_INVALIDPARAMERR; }

    // 假设签名长度是 64 字节
    memset(pSignature, 0x8B, sizeof(ECCSIGNATUREBLOB));
    return SAR_OK;
}

#ifdef SKF_HAS_ECCDECRYPT
ULONG DEVAPI SKF_ECCDecrypt(
    HCONTAINER hContainer,
    ECCCIPHERBLOB *pCipherBlob,
    BYTE *pbPlainText,
    ULONG *pulPlainTextLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulPlainTextLen);
    ULONG check = CheckEccCipherBlobValidity(pCipherBlob);
    if (check != SAR_OK) {
        return check;
    }

    ULONG required_len = pCipherBlob->CipherLen;
    if (pbPlainText == NULL || *pulPlainTextLen < required_len) {
        *pulPlainTextLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbPlainText, 0x9C, required_len);
    *pulPlainTextLen = required_len;
    return SAR_OK;
}
#endif

/* 7.6.14 SKF_ECCVerify */
ULONG DEVAPI SKF_ECCVerify(
    DEVHANDLE hDev,
    ECCPUBLICKEYBLOB *pECCPubKeyBlob,
    BYTE *pbData,
    ULONG ulDataLen,
    ECCSIGNATUREBLOB *pSignature) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pECCPubKeyBlob == NULL || pbData == NULL || pSignature == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.15 SKF_ECCExportSessionKey */
ULONG DEVAPI SKF_ECCExportSessionKey(
    HCONTAINER hContainer,
    ULONG ulAlgId,
    ECCPUBLICKEYBLOB *pPubKey,
    ECCCIPHERBLOB *pData,
    HANDLE *phSessionKey) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pPubKey);
    CHECK_NOT_NULL(pData);
    CHECK_NOT_NULL(phSessionKey);

    InitEccCipherBlob(pData, 16);
    *phSessionKey = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.16 SKF_ExtECCEncrypt */
ULONG DEVAPI SKF_ExtECCEncrypt(
    DEVHANDLE hDev,
    ECCPUBLICKEYBLOB *pECCPubKeyBlob,
    BYTE *pbPlainText,
    ULONG ulPlainTextLen,
    ECCCIPHERBLOB *pCipherText) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pECCPubKeyBlob);
    CHECK_NOT_NULL(pCipherText);
    if (pbPlainText == NULL) { return SAR_INVALIDPARAMERR; }

    InitEccCipherBlob(pCipherText, ulPlainTextLen);
    return SAR_OK;
}

/* 7.6.17 SKF_ExtECCDecrypt */
ULONG DEVAPI SKF_ExtECCDecrypt(
    DEVHANDLE hDev,
    ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
    ECCCIPHERBLOB *pCipherText,
    BYTE *pbPlainText,
    ULONG *pulPlainTextLen) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pECCPriKeyBlob);
    CHECK_NOT_NULL(pulPlainTextLen);
    ULONG check = CheckEccCipherBlobValidity(pCipherText);
    if (check != SAR_OK) {
        return check;
    }

    ULONG required_len = pCipherText->CipherLen;
    if (pbPlainText == NULL || *pulPlainTextLen < required_len) {

        printf("pbPlainText is null or too small,pulPlainTextLen=%lu \n", *pulPlainTextLen);
        *pulPlainTextLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbPlainText, 0xCF, required_len);
    *pulPlainTextLen = required_len;
    return SAR_OK;
}

/* 7.6.18 SKF_ExtECCSign */
ULONG DEVAPI SKF_ExtECCSign(
    DEVHANDLE hDev,
    ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
    BYTE *pbData,
    ULONG ulDataLen,
    ECCSIGNATUREBLOB *pSignature) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pECCPriKeyBlob);
    CHECK_NOT_NULL(pSignature);
    if (pbData == NULL) { return SAR_INVALIDPARAMERR; }

    memset(pSignature, 0xDA, sizeof(ECCSIGNATUREBLOB));
    return SAR_OK;
}

/* 7.6.19 SKF_ExtECCVerify */
ULONG DEVAPI SKF_ExtECCVerify(
    DEVHANDLE hDev,
    ECCPUBLICKEYBLOB *pECCPubKeyBlob,
    BYTE *pbData,
    ULONG ulDataLen,
    ECCSIGNATUREBLOB *pSignature) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pECCPubKeyBlob == NULL || pbData == NULL || pSignature == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.20 SKF_GenerateAgreementDataWithECC */
ULONG DEVAPI SKF_GenerateAgreementDataWithECC(
    HCONTAINER hContainer,
    ULONG ulAlgId,
    ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
    BYTE *pbID,
    ULONG ulIDLen,
    HANDLE *phAgreementHandle) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pTempECCPubKeyBlob);
    CHECK_NOT_NULL(phAgreementHandle);
    if (ulAlgId == 0) { return SAR_INVALIDPARAMERR; }

    *phAgreementHandle = (HANDLE) MOCK_AGREEMENT_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.21 SKF_GenerateAgreementDataAndKeyWithECC */
ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
    HANDLE hContainer,
    ULONG ulAlgId,
    ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
    ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
    ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
    BYTE *pbID,
    ULONG ulIDLen,
    BYTE *pbSponsorID,
    ULONG ulSponsorIDLen,
    HANDLE *phKeyHandle) {
    if (hContainer != (HANDLE) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pSponsorECCPubKeyBlob);
    CHECK_NOT_NULL(phKeyHandle);

    *phKeyHandle = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.22 SKF_GenerateKeyWithECC */
ULONG DEVAPI SKF_GenerateKeyWithECC(
    HANDLE hAgreementHandle,
    ECCPUBLICKEYBLOB *pECCPubKeyBlob,
    ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
    BYTE *pbID,
    ULONG ulIDLen,
    HANDLE *phKeyHandle) {
    if (hAgreementHandle != (HANDLE) MOCK_AGREEMENT_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pECCPubKeyBlob);
    CHECK_NOT_NULL(phKeyHandle);

    *phKeyHandle = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.23 SKF_ExportPublicKey */
ULONG DEVAPI SKF_ExportPublicKey(
    HCONTAINER hContainer,
    BOOL bSignFlag,
    BYTE *pbBlob,
    ULONG *pulBlobLen) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulBlobLen);

    ULONG required_len = 256;
    if (pbBlob == NULL || *pulBlobLen < required_len) {
        *pulBlobLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbBlob, 0xEB, required_len);
    *pulBlobLen = required_len;
    return SAR_OK;
}

/* 7.6.24 SKF_ImportSessionKey */
ULONG DEVAPI SKF_ImportSessionKey(
    HCONTAINER hContainer,
    ULONG ulAlgId,
    BYTE *pbWrapedData,
    ULONG ulWrapedLen,
    HANDLE *phKey) {
    if (hContainer != (HCONTAINER) MOCK_CONTAINER_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phKey);
    if (pbWrapedData == NULL) { return SAR_INVALIDPARAMERR; }

    *phKey = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.25 SKF_SetSymmKey */
ULONG DEVAPI SKF_SetSymmKey(
    DEVHANDLE hDev,
    BYTE *pbKey,
    ULONG ulAlgID,
    HANDLE *phKey) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phKey);
    if (pbKey == NULL) { return SAR_INVALIDPARAMERR; }

    *phKey = (HANDLE) MOCK_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.26 SKF_EncryptInit */
ULONG DEVAPI SKF_EncryptInit(
    HANDLE hKey,
    BLOCKCIPHERPARAM EncryptParam) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    // 假设 EncryptParam 是一个值传递的结构体，不需要 NULL 检查
    return SAR_OK;
}

/* 7.6.27 SKF_Encrypt */
ULONG DEVAPI SKF_Encrypt(
    HANDLE hKey,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbEncryptedData,
    ULONG *pulEncryptedLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulEncryptedLen);
    if (pbData == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = ulDataLen + 16;
    if (pbEncryptedData == NULL || *pulEncryptedLen < required_len) {
        *pulEncryptedLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbEncryptedData, 0xFC, required_len);
    *pulEncryptedLen = required_len;
    return SAR_OK;
}

/* 7.6.28 SKF_EncryptUpdate */
ULONG DEVAPI SKF_EncryptUpdate(
    HANDLE hKey,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbEncryptedData,
    ULONG *pulEncryptedLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulEncryptedLen);
    if (pbData == NULL) { return SAR_INVALIDPARAMERR; }

    // 假设返回的数据长度为 ulDataLen
    if (pbEncryptedData == NULL || *pulEncryptedLen < ulDataLen) {
        *pulEncryptedLen = ulDataLen;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbEncryptedData, 0xFD, ulDataLen);
    *pulEncryptedLen = ulDataLen;
    return SAR_OK;
}

/* 7.6.29 SKF_EncryptFinal */
ULONG DEVAPI SKF_EncryptFinal(
    HANDLE hKey,
    BYTE *pbEncryptedData,
    ULONG *pulEncryptedDataLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulEncryptedDataLen);

    ULONG required_len = 8;
    if (pbEncryptedData == NULL || *pulEncryptedDataLen < required_len) {
        *pulEncryptedDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbEncryptedData, 0xFE, required_len);
    *pulEncryptedDataLen = required_len;
    return SAR_OK;
}

/* 7.6.30 SKF_DecryptInit */
ULONG DEVAPI SKF_DecryptInit(
    HANDLE hKey,
    BLOCKCIPHERPARAM DecryptParam) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    return SAR_OK;
}

/* 7.6.31 SKF_Decrypt */
ULONG DEVAPI SKF_Decrypt(
    HANDLE hKey,
    BYTE *pbEncryptedData,
    ULONG ulEncryptedLen,
    BYTE *pbData,
    ULONG *pulDataLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulDataLen);
    if (pbEncryptedData == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = ulEncryptedLen - 16;
    if (pbData == NULL || *pulDataLen < required_len) {
        *pulDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbData, 0x1B, required_len);
    *pulDataLen = required_len;
    return SAR_OK;
}

/* 7.6.32 SKF_DecryptUpdate */
ULONG DEVAPI SKF_DecryptUpdate(
    HANDLE hKey,
    BYTE *pbEncryptedData,
    ULONG ulEncryptedLen,
    BYTE *pbData,
    ULONG *pulDataLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulDataLen);
    if (pbEncryptedData == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = ulEncryptedLen;
    if (pbData == NULL || *pulDataLen < required_len) {
        *pulDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbData, 0x2C, required_len);
    *pulDataLen = required_len;
    return SAR_OK;
}

/* 7.6.33 SKF_DecryptFinal */
ULONG DEVAPI SKF_DecryptFinal(
    HANDLE hKey,
    BYTE *pbDecryptedData,
    ULONG *pulDecryptedDataLen) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulDecryptedDataLen);

    ULONG required_len = 8;
    if (pbDecryptedData == NULL || *pulDecryptedDataLen < required_len) {
        *pulDecryptedDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbDecryptedData, 0x3D, required_len);
    *pulDecryptedDataLen = required_len;
    return SAR_OK;
}

/* 7.6.34 SKF_DigestInit */
ULONG DEVAPI SKF_DigestInit(
    DEVHANDLE hDev,
    ULONG ulAlgID,
    ECCPUBLICKEYBLOB *pPubKey,
    BYTE *pbID,
    ULONG ulIDLen,
    HANDLE *phHash) {
    if (hDev != (DEVHANDLE) MOCK_DEV_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(phHash);
    if (ulAlgID == 0) { return SAR_INVALIDPARAMERR; }

    *phHash = (HANDLE) MOCK_HASH_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.35 SKF_Digest */
ULONG DEVAPI SKF_Digest(
    HANDLE hHash,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbHashData,
    ULONG *pulHashLen) {
    if (hHash != (HANDLE) MOCK_HASH_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulHashLen);
    if (pbData == NULL || ulDataLen == 0) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 32; // 假设 SHA256
    if (pbHashData == NULL || *pulHashLen < required_len) {
        *pulHashLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbHashData, 0x4E, required_len);
    *pulHashLen = required_len;
    return SAR_OK;
}

/* 7.6.36 SKF_DigestUpdate */
ULONG DEVAPI SKF_DigestUpdate(
    HANDLE hHash,
    BYTE *pbData,
    ULONG ulDataLen) {
    if (hHash != (HANDLE) MOCK_HASH_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbData == NULL || ulDataLen == 0) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.37 SKF_DigestFinal */
ULONG DEVAPI SKF_DigestFinal(
    HANDLE hHash,
    BYTE *pHashData,
    ULONG *pulHashLen) {
    if (hHash != (HANDLE) MOCK_HASH_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulHashLen);

    ULONG required_len = 32;
    if (pHashData == NULL || *pulHashLen < required_len) {
        *pulHashLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pHashData, 0x5F, required_len);
    *pulHashLen = required_len;
    return SAR_OK;
}

/* 7.6.38 SKF_MacInit */
ULONG DEVAPI SKF_MacInit(
    HANDLE hKey,
    BLOCKCIPHERPARAM *pMacParam,
    HANDLE *phMac) {
    if (hKey != (HANDLE) MOCK_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pMacParam);
    CHECK_NOT_NULL(phMac);

    *phMac = (HANDLE) MOCK_MAC_KEY_HANDLE_VALUE;
    return SAR_OK;
}

/* 7.6.39 SKF_Mac */
ULONG DEVAPI SKF_Mac(
    HANDLE hMac,
    BYTE *pbData,
    ULONG ulDataLen,
    BYTE *pbMacData,
    ULONG *pulMacLen) {
    if (hMac != (HANDLE) MOCK_MAC_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulMacLen);
    if (pbData == NULL) { return SAR_INVALIDPARAMERR; }

    ULONG required_len = 16;
    if (pbMacData == NULL || *pulMacLen < required_len) {
        *pulMacLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbMacData, 0x70, required_len);
    *pulMacLen = required_len;
    return SAR_OK;
}

/* 7.6.40 SKF_MacUpdate */
ULONG DEVAPI SKF_MacUpdate(
    HANDLE hMac,
    BYTE *pbData,
    ULONG ulDataLen) {
    if (hMac != (HANDLE) MOCK_MAC_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    if (pbData == NULL) { return SAR_INVALIDPARAMERR; }
    return SAR_OK;
}

/* 7.6.41 SKF_MacFinal */
ULONG DEVAPI SKF_MacFinal(
    HANDLE hMac,
    BYTE *pbMacData,
    ULONG *pulMacDataLen) {
    if (hMac != (HANDLE) MOCK_MAC_KEY_HANDLE_VALUE) { return SAR_INVALIDHANDLEERR; }
    CHECK_NOT_NULL(pulMacDataLen);

    ULONG required_len = 16;
    if (pbMacData == NULL || *pulMacDataLen < required_len) {
        *pulMacDataLen = required_len;
        return SAR_BUFFER_TOO_SMALL;
    }

    memset(pbMacData, 0x81, required_len);
    *pulMacDataLen = required_len;
    return SAR_OK;
}

/* 7.6.42 SKF_CloseHandle */
ULONG DEVAPI SKF_CloseHandle(
    HANDLE hHandle) {
    if (hHandle == (HANDLE) MOCK_DEV_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_APP_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_CONTAINER_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_KEY_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_HASH_KEY_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_AGREEMENT_KEY_HANDLE_VALUE ||
        hHandle == (HANDLE) MOCK_MAC_KEY_HANDLE_VALUE) {
        return SAR_OK;
    }

    return SAR_INVALIDHANDLEERR;
}
