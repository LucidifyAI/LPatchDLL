// LPatchDLL.cpp  —  Minimal Unity-safe BLE advertisements + CGX detection
// No precompiled headers required. Build x64, /std:c++17, link windowsapp.

#include <atomic>
#include <cstdint>
#include <cwchar>
#include <mutex>
#include <queue>
#include <string>
#include <vector>
#include <cstdarg>   // <- for va_list, va_start, va_end

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Devices.Enumeration.h>
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Devices.Bluetooth.Advertisement.h>
#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#pragma comment(lib, "windowsapp")

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Devices::Enumeration;
using namespace Windows::Devices::Bluetooth;
using namespace Windows::Devices::Bluetooth::Advertisement;
using namespace Windows::Devices::Bluetooth::GenericAttributeProfile;

// -------------------- error buffer --------------------

static std::mutex g_errMx;
static wchar_t g_err[2048] = L"OK";

static void ClearError() {
    std::lock_guard<std::mutex> lk(g_errMx);
    wcscpy_s(g_err, L"OK");
}
static void SaveError(const wchar_t* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_errMx);
    va_list ap; va_start(ap, fmt);
    vswprintf_s(g_err, fmt, ap);
    va_end(ap);
}

extern "C" __declspec(dllexport) void __cdecl GetError(wchar_t* outBuf, int outChars) {
    if (!outBuf || outChars <= 0) return;
    std::lock_guard<std::mutex> lk(g_errMx);
    wcsncpy_s(outBuf, outChars, g_err, _TRUNCATE);  // 4 args
}

// -------------------- CGX UUIDs --------------------
// <guiddef.h> via <windows.h> or <Unknwn.h>
#define INITGUID
#include <guiddef.h>
DEFINE_GUID(kCgxServiceUuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x01);
DEFINE_GUID(kCgxChar1Uuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x03);
DEFINE_GUID(kCgxChar2Uuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x04);
// -------------------- init / shutdown --------------------
static std::atomic_bool g_inited{ false };

extern "C" __declspec(dllexport) int __cdecl Ble_Ping() { return 42; }

extern "C" __declspec(dllexport) bool __cdecl Ble_Init() {
    if (g_inited.load(std::memory_order_acquire)) return true;
    try {
        // MTA is fine for AdvertisementWatcher; avoids STA headaches.
        winrt::init_apartment(apartment_type::multi_threaded);
        g_inited.store(true, std::memory_order_release);
        ClearError();
        return true;
    }
    catch (hresult_error const& ex) {
        SaveError(L"Ble_Init: %s", ex.message().c_str());
        return false;
    }
    catch (...) {
        SaveError(L"Ble_Init: unknown");
        return false;
    }
}

extern "C" __declspec(dllexport) void __cdecl Ble_Shutdown() {
    try {
        if (g_inited.exchange(false)) {
            // Let WinRT tear down when DLL unloads; don’t uninit apartment here
            // because Unity may still hold WinRT state. Just clear error.
        }
        ClearError();
    }
    catch (...) { /* swallow */ }
}

// -------------------- advertisement queue --------------------

struct AdvUpdate {
    wchar_t  id[260];         // "BluetoothLE#BluetoothLE-adapter-XX:.."
    wchar_t  name[128];       // LocalName (optional)
    bool     hasName;
    bool     isConnectable;
    int8_t   rssi;
    uint64_t address;         // 48-bit MAC in uint64
    int      serviceCount;    // how many valid entries in services[]
    guid     services[8];     // first 8 advertised service UUIDs
};

static std::mutex g_advMx;
static std::queue<AdvUpdate> g_advQ;
static BluetoothLEAdvertisementWatcher g_watcher{ nullptr };
static std::atomic_bool g_advRunning{ false };

static void MakeBleIdFromAddress(uint64_t addr, wchar_t* dst, size_t dstChars) {
    if (!dst || dstChars == 0) return;
    swprintf_s(dst, dstChars, L"BluetoothLE#BluetoothLE-adapter-%02X:%02X:%02X:%02X:%02X:%02X",
        (int)((addr >> 40) & 0xFF), (int)((addr >> 32) & 0xFF), (int)((addr >> 24) & 0xFF),
        (int)((addr >> 16) & 0xFF), (int)((addr >> 8) & 0xFF), (int)(addr & 0xFF));
}

extern "C" __declspec(dllexport) int __cdecl GetAdvUpdateSize() {
    return (int)sizeof(AdvUpdate);
}

extern "C" __declspec(dllexport) void __cdecl StartAdvertisementWatch() {
    if (!g_inited.load()) Ble_Init();
    if (g_advRunning.exchange(true)) return; // already running

    try {
        g_watcher = BluetoothLEAdvertisementWatcher();
        g_watcher.ScanningMode(BluetoothLEScanningMode::Active);

        g_watcher.Received([](auto const&, BluetoothLEAdvertisementReceivedEventArgs const& args) {
            AdvUpdate u{}; // zero-init
            u.address = args.BluetoothAddress();
            u.rssi = (int8_t)args.RawSignalStrengthInDBm();
            u.isConnectable = args.IsConnectable();
            MakeBleIdFromAddress(u.address, u.id, _countof(u.id));

            // name
            auto ln = args.Advertisement().LocalName();
            u.hasName = ln.size() > 0;
            if (u.hasName) {
                wcsncpy_s(u.name, _countof(u.name), ln.c_str(), _TRUNCATE);
            }

            // services
            auto su = args.Advertisement().ServiceUuids();
            uint32_t n = su ? su.Size() : 0;
            if (n > 8) n = 8;
            u.serviceCount = (int)n;
            for (uint32_t i = 0; i < n; ++i) {
                u.services[i] = su.GetAt(i);
            }

            // enqueue
            {
                std::lock_guard<std::mutex> lk(g_advMx);
                g_advQ.push(u);
            }
        });

        g_watcher.Start();
        ClearError();
    }
    catch (hresult_error const& ex) {
        SaveError(L"StartAdvertisementWatch: %s", ex.message().c_str());
        g_advRunning.store(false);
    }
    catch (...) {
        SaveError(L"StartAdvertisementWatch: unknown");
        g_advRunning.store(false);
    }
}

extern "C" __declspec(dllexport) void __cdecl StopAdvertisementWatch() {
    try {
        if (g_watcher) {
            g_watcher.Stop();
            g_watcher = nullptr;
        }
        g_advRunning.store(false);
        ClearError();
    }
    catch (...) { /**/ }
}

extern "C" __declspec(dllexport) bool __cdecl PollAdvertisement(AdvUpdate* out) {
    if (!out) return false;
    std::lock_guard<std::mutex> lk(g_advMx);
    if (g_advQ.empty()) return false;
    *out = g_advQ.front();
    g_advQ.pop();
    return true;
}

// -------------------- address → DeviceInformation.Id --------------------

extern "C" __declspec(dllexport) bool __cdecl ResolveIdFromAddress(uint64_t address,
    wchar_t* outId,
    int outChars)
{
    if (!outId || outChars <= 0) { SaveError(L"ResolveIdFromAddress: bad out buf"); return false; }
    outId[0] = L'\0';
    try {
        auto dev = BluetoothLEDevice::FromBluetoothAddressAsync(address).get();
        if (!dev) { SaveError(L"ResolveIdFromAddress: device null"); return false; }

        winrt::hstring id = dev.DeviceInformation().Id();   // explicit type
        wcsncpy_s(outId, outChars, id.c_str(), _TRUNCATE);
        ClearError();
        return true;
    }
    catch (hresult_error const& ex) {
        SaveError(L"ResolveIdFromAddress: %s", ex.message().c_str());
        return false;
    }
    catch (...) {
        SaveError(L"ResolveIdFromAddress: unknown");
        return false;
    }
}

// -------------------- CGX service presence --------------------
static bool HasServiceOn(BluetoothLEDevice const& dev, guid const& svc, BluetoothCacheMode mode) {
    auto r = dev.GetGattServicesForUuidAsync(svc, mode).get();
    return r.Status() == GattCommunicationStatus::Success && r.Services().Size() > 0;
}

extern "C" __declspec(dllexport) bool __cdecl HasCgxService(const wchar_t* deviceId, bool preferCached) {
    if (!deviceId || !*deviceId) { SaveError(L"HasCgxService: empty deviceId"); return false; }
    try {
        auto dev = BluetoothLEDevice::FromIdAsync(deviceId).get();
        if (!dev) { SaveError(L"HasCgxService: FromIdAsync null"); return false; }

        bool ok = false;
        if (preferCached) {
            ok = HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Cached)
                || HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Uncached);
        }
        else {
            ok = HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Uncached)
                || HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Cached);
        }
        ClearError();
        return ok;
    }
    catch (hresult_error const& ex) {
        SaveError(L"HasCgxService: %s", ex.message().c_str());
        return false;
    }
    catch (...) {
        SaveError(L"HasCgxService: unknown");
        return false;
    }
}
