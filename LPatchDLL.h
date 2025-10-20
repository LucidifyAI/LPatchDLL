#pragma once
#include <cstdint>   // uint64_t, int8_t
#include <winrt/base.h> // winrt::guid

#if defined(_MSC_VER)
#define DLL_EXPORT __declspec(dllexport)
#define CDECL __cdecl
#else
#define DLL_EXPORT
#define CDECL
#endif

extern "C" {

    // -------- error --------
    struct ErrorMessage { wchar_t msg[2048]; };

    // -------- adverts (layout matches your C# AdvUpdate) --------
    struct AdvUpdate {
        wchar_t  id[260];
        wchar_t  name[128];
        bool     hasName;
        bool     isConnectable;
        int8_t   rssi;
        uint64_t address;
        int      serviceCount;
        winrt::guid services[8]; // matches C# Guid[8]
    };

    // -------- stream (placeholder) --------
    struct StreamChunk {
        int       size;
        long long timestamp100ns;
        uint8_t   data[512];
    };

    // -------- base API --------
    DLL_EXPORT int               CDECL Ble_Ping();
    DLL_EXPORT const wchar_t* CDECL Ble_Version();
    DLL_EXPORT bool              CDECL Ble_Init();
    DLL_EXPORT void              CDECL Ble_Shutdown();
    DLL_EXPORT void              CDECL GetError(ErrorMessage* out);

    // -------- adverts API --------
    DLL_EXPORT void              CDECL StartAdvertisementWatch();
    DLL_EXPORT void              CDECL StopAdvertisementWatch();
    DLL_EXPORT int               CDECL GetAdvUpdateSize();
    DLL_EXPORT bool              CDECL PollAdvertisement(AdvUpdate* out);

    // -------- resolve API (stub) --------
    DLL_EXPORT bool              CDECL ResolveIdFromAddress(uint64_t address,
        wchar_t* outId,
        int outChars);

    // -------- CGX API (stubs) --------
    DLL_EXPORT bool              CDECL HasCgxService(wchar_t* deviceId, bool preferCached);
    DLL_EXPORT bool              CDECL SubscribeCgxEeg(wchar_t* deviceId, bool block);
    DLL_EXPORT bool              CDECL UnsubscribeCgxEeg(const wchar_t* deviceId, bool block);

    // -------- stream poll (stub) --------
    DLL_EXPORT int               CDECL GetStreamChunkSize();
    DLL_EXPORT bool              CDECL PollStreamChunk(StreamChunk* out, bool block);

    // -------- legacy/compat --------
    DLL_EXPORT void              CDECL Quit();

} // extern "C"
