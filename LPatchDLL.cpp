// LPatchDLL.cpp  —  Minimal Unity-safe BLE advertisements + CGX detection
// No precompiled headers required. Build x64, /std:c++17, link windowsapp.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>   // DWORD, GetCurrentThreadId, RPC_E_CHANGED_MODE
#include <atomic>
#include <cstdint>
#include <cwchar>
#include <mutex>
#include <queue>
#include <string>
#include <vector>
#include <cstdarg>   // <- for va_list, va_start, va_end
#include <deque>

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

//============Streaming
#include <winrt/Windows.Storage.Streams.h>
using namespace Windows::Storage::Streams;

// -------------------- error buffer --------------------

static std::mutex g_errMx;
static wchar_t g_err[2048] = L"OK";

// --- unified reassembly state (protected by g_dataMx) ---
static std::vector<uint8_t> g_pktBuf;
static bool                 g_haveSync = false;
static const uint8_t        kSyncA = 0xFF;
static const uint8_t        kSyncB = 0xF8;

static void ClearError() { std::lock_guard<std::mutex> lk(g_errMx); wcscpy_s(g_err, L"OK"); }
static void SaveError(const wchar_t* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_errMx);
    va_list ap; va_start(ap, fmt); vswprintf_s(g_err, fmt, ap); va_end(ap);
}
static event_token g_advRecvTok{};
static event_token g_advStoppedTok{};
// Struct that matches C# ErrorMessage
struct ErrorMessage { wchar_t msg[2048]; };

// globals
static std::atomic<bool> g_resetRequested{ false };
static inline bool IsSync(uint8_t b) { return b == 0xFF || b == 0xF8; }
static void RequestAssemblerReset() { g_resetRequested.store(true, std::memory_order_relaxed); }


extern "C" __declspec(dllexport) void __cdecl GetError(ErrorMessage* outMsg) {
    if (!outMsg) return;
    std::lock_guard<std::mutex> lk(g_errMx);
    wcsncpy_s(outMsg->msg, _countof(outMsg->msg), g_err, _TRUNCATE);
}

// -------------------- CGX UUIDs --------------------
// <guiddef.h> via <windows.h> or <Unknwn.h>
#define INITGUID
#include <guiddef.h>
DEFINE_GUID(kCgxServiceUuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x01);
DEFINE_GUID(kCgxChar1Uuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x03);
DEFINE_GUID(kCgxChar2Uuid, 0x2456e1b9, 0x26e2, 0x8f83, 0xe7, 0x44, 0xf3, 0x4f, 0x01, 0xe9, 0xd7, 0x04);

// ---------- Streaming state ----------
static BluetoothLEDevice                         g_dev{ nullptr };
static GattDeviceService                         g_svc{ nullptr };
static GattCharacteristic                        g_ch1{ nullptr };
static GattCharacteristic                        g_ch2{ nullptr };
static event_token                               g_tok1{};
static event_token                               g_tok2{};
static std::atomic_bool                          g_subscribed{ false };
static winrt::hstring                            g_curDeviceId;

// For PollData queue (if you implemented it)
struct NativeChunk {
    std::vector<uint8_t> bytes;
    guid                 charUuid{};
    int64_t              ts100ns{ 0 };
};

static std::mutex              g_dataMx;
static std::deque<NativeChunk> g_dataQ;
static size_t                  g_queuedBytes = 0;
static constexpr size_t        kMaxQueuedBytes = (1u << 20); // 1 MB cap

// -------------------- init / shutdown --------------------

static std::atomic<DWORD> g_initTid{ 0 };   // thread that called Ble_Init
static std::atomic<bool>  g_inited{ false };
// Feed raw BLE bytes (from either characteristic) and emit full 37B frames
static void EnqueueAssembled(std::vector<uint8_t>&& v)
{
    if (v.empty()) return;
    std::lock_guard<std::mutex> lk(g_dataMx);        // serialize both EEG streams

    if (g_resetRequested.exchange(false)) { g_pktBuf.clear(); g_haveSync = false; }

    auto emit_frame = [&](const std::vector<uint8_t>& frame) {
        // Cap queue to 1 MB (matches existing policy)
        while (g_queuedBytes + frame.size() > kMaxQueuedBytes && !g_dataQ.empty()) {
            g_queuedBytes -= g_dataQ.front().bytes.size();
            g_dataQ.pop_front();
        }
        NativeChunk nc;
        nc.bytes = frame;                      // copy into a new node
        nc.charUuid = kCgxServiceUuid;           // mark as unified EEG stream
        nc.ts100ns = winrt::clock::now().time_since_epoch().count();
        g_queuedBytes += nc.bytes.size();
        g_dataQ.emplace_back(std::move(nc));
    };

    // Byte-wise state machine: find sync, then fill to 37 bytes
    for (uint8_t b : v)
    {
        if (!g_haveSync) { if (IsSync(b)) { g_pktBuf.clear(); g_pktBuf.push_back(b); g_haveSync = true; } continue; }

        if (IsSync(b) && g_pktBuf.size() < 37) { g_pktBuf.clear(); g_pktBuf.push_back(b); }
        else { g_pktBuf.push_back(b); }

        if (g_pktBuf.size() == 37) { emit_frame(g_pktBuf); g_pktBuf.clear(); g_haveSync = false; }
        else if (g_pktBuf.size() > 37) { g_pktBuf.clear(); g_haveSync = IsSync(b); if (g_haveSync) g_pktBuf.push_back(b); }
    }
}

extern "C" __declspec(dllexport) int __cdecl Ble_Ping() { return 42; }

extern "C" __declspec(dllexport) const wchar_t* __cdecl Ble_Version() {
    static const wchar_t* kVer = L"LPatchDLL 1.0 (CGX BLE stream)";
    return kVer;
}
//=======================Close functions
// Helper: explicitly Close() any WinRT object that supports IClosable
// Helper: explicitly Close() any WinRT object that supports IClosable (C++17-safe)
template <typename T>
static inline void CloseIfIClosable(T& obj) {
    if (!obj) return;
    try {
        if (auto closable = obj.try_as<winrt::Windows::Foundation::IClosable>()) {
            closable.Close();
        }
    }
    catch (...) { /* swallow */ }
    obj = nullptr;
}


extern "C" __declspec(dllexport) bool __cdecl Ble_Init() {
    // If already initialized on *this* thread, it's fine.
    if (g_inited.load(std::memory_order_acquire) && g_initTid.load() == GetCurrentThreadId()) {
        return true;
    }

    try {
        // Attempt to initialize a WinRT apartment for this thread.
        // If the thread is already STA/MTA in a conflicting mode, C++/WinRT throws
        // hresult_error with RPC_E_CHANGED_MODE — we treat that as "already ok".
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
    }
    catch (winrt::hresult_error const& e) {
        if ((uint32_t)e.code() == (uint32_t)RPC_E_CHANGED_MODE) {
            // Different apartment already set — safe to proceed.
        }
        else {
            SaveError(L"Ble_Init: %s", e.message().c_str());
            return false;
        }
    }
    catch (...) {
        SaveError(L"Ble_Init: unknown exception");
        return false;
    }

    g_initTid.store(GetCurrentThreadId(), std::memory_order_release);
    g_inited.store(true, std::memory_order_release);
    ClearError();
    return true;
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
extern "C" __declspec(dllexport) void __cdecl Ble_Quit() {
    try {
        // Stop notifications if active
        if (g_subscribed.exchange(false)) {
            try {
                if (g_ch1) g_ch1.ValueChanged(g_tok1);
                if (g_ch2) g_ch2.ValueChanged(g_tok2);
            }
            catch (...) {}
        }
        g_tok1 = {}; g_tok2 = {};

        try {
            if (g_ch1) g_ch1.WriteClientCharacteristicConfigurationDescriptorAsync(
                Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue::None).get();
        }
        catch (...) {}
        try {
            if (g_ch2) g_ch2.WriteClientCharacteristicConfigurationDescriptorAsync(
                Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue::None).get();
        }
        catch (...) {}

        // NEW: close session and objects explicitly
        // Close the GATT session via the service, if available
        try {
            if (g_svc) {
                auto sess = g_svc.Session();   // Session hangs off the service
                if (sess) {
                    // GattSession implements IClosable, so Close() is available
                    sess.Close();
                }
            }
        }
        catch (...) {}
        CloseIfIClosable(g_ch1);
        CloseIfIClosable(g_ch2);
        CloseIfIClosable(g_svc);
        CloseIfIClosable(g_dev);

        // Clear queue (you already do this)
        {
            std::lock_guard<std::mutex> lk(g_dataMx);
            g_dataQ.clear();
            g_queuedBytes = 0;
        }

        // Optional: tiny back-off helps after back-to-back reconnect attempts
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        // Leave the apartment alone (Unity often keeps WinRT state)
        ClearError();
    }
    catch (winrt::hresult_error const& e) { SaveError(L"Ble_Quit: %s", e.message().c_str()); }
    catch (...) { SaveError(L"Ble_Quit: unknown exception"); }
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

        g_advRecvTok = g_watcher.Received([](auto const&, BluetoothLEAdvertisementReceivedEventArgs const& args) {
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

extern "C" __declspec(dllexport) void __cdecl StopAdvertisementWatch()
{
    try {
        g_advRunning.store(false);

        // Grab and clear the global without holding other locks
        auto watcher = std::move(g_watcher);
        g_watcher = nullptr;
        if (!watcher) { ClearError(); return; }

        // 1) Revoke handlers first (ignore errors)
        try { watcher.Received(g_advRecvTok); }
        catch (...) {}
        try { watcher.Stopped(g_advStoppedTok); }
        catch (...) {}
        g_advRecvTok = {}; g_advStoppedTok = {};

        // 2) Stop the watcher off the Unity main thread with a timeout
        std::atomic<bool> done{ false };
        std::thread([w = std::move(watcher), &done]() mutable {
            try {
                // Make sure we’re in the same apartment type you used to create it.
                // If you created on MTA at startup, ensure this thread is also MTA:
                winrt::init_apartment(winrt::apartment_type::multi_threaded);

                // Only call Stop if it looks started
                using Status = winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus;
                auto st = w.Status();
                if (st == Status::Started || st == Status::Stopping || st == Status::Created) {
                    w.Stop();
                }
            }
            catch (...) {}
            done.store(true, std::memory_order_release);
        }).detach();

        // 3) Wait briefly so we don’t leak watchers, but don’t hang the editor
        using namespace std::chrono_literals;
        auto t0 = std::chrono::steady_clock::now();
        while (!done.load(std::memory_order_acquire) &&
            std::chrono::steady_clock::now() - t0 < 1500ms)
        {
            std::this_thread::sleep_for(10ms);
        }

        ClearError();
    }
    catch (...) { /* swallow to avoid crashing Unity */ }
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

        winrt::hstring id = dev.DeviceInformation().Id();
        wcsncpy_s(outId, outChars, id.c_str(), _TRUNCATE);

        // NEW: explicitly close the transient device
        try { winrt::Windows::Foundation::IClosable(dev).Close(); }
        catch (...) {}

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
        // NEW: bias Uncached first unless caller *insists* on cached
        if (preferCached) {
            ok = HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Cached)
                || HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Uncached);
        }
        else {
            ok = HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Uncached)
                || HasServiceOn(dev, kCgxServiceUuid, BluetoothCacheMode::Cached);
        }

        // NEW: explicitly close probe device before returning
        try { winrt::Windows::Foundation::IClosable(dev).Close(); }
        catch (...) {}

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



static inline void EnqueueChunk(std::vector<uint8_t>&& v, guid const& chUuid) {
    std::lock_guard<std::mutex> lk(g_dataMx);
    if (v.empty()) return;
    // Drop oldest if we’d exceed the cap
    while (g_queuedBytes + v.size() > kMaxQueuedBytes && !g_dataQ.empty()) {
        g_queuedBytes -= g_dataQ.front().bytes.size();
        g_dataQ.pop_front();
    }
    NativeChunk nc;
    nc.bytes = std::move(v);
    nc.charUuid = chUuid;
    nc.ts100ns = winrt::clock::now().time_since_epoch().count();
    g_queuedBytes += nc.bytes.size();
    g_dataQ.emplace_back(std::move(nc));
}
#pragma pack(push, 1)
struct BLEDataNative {
    wchar_t deviceId[260];
    wchar_t serviceUuid[64];
    wchar_t characteristicUuid[64];
    int32_t size;
    uint8_t buf[2050];
};
#pragma pack(pop)

extern "C" __declspec(dllexport) int __cdecl GetBleDataSize() {
    return (int)sizeof(BLEDataNative);
}

// Optional: StreamChunk path (smaller fixed buffer + timestamp)
#pragma pack(push, 1)
struct StreamChunkNative {
    int32_t  size;
    int64_t  timestamp100ns;
    uint8_t  data[512];
};
#pragma pack(pop)

extern "C" __declspec(dllexport) int __cdecl GetStreamChunkSize() {
    return (int)sizeof(StreamChunkNative);
}
extern "C" __declspec(dllexport) bool __cdecl SubscribeCgxEeg(const wchar_t* deviceId, bool /*block*/) {
    if (!deviceId || !*deviceId) { SaveError(L"SubscribeCgxEeg: empty deviceId"); return false; }
    try {
        // Tear down any previous state
        RequestAssemblerReset();
        if (g_subscribed.exchange(false)) {
            try {
                if (g_ch1) g_ch1.ValueChanged(g_tok1);
                if (g_ch2) g_ch2.ValueChanged(g_tok2);
            }
            catch (...) {}
            g_tok1 = {}; g_tok2 = {};
            g_ch1 = nullptr; g_ch2 = nullptr; g_svc = nullptr; g_dev = nullptr;
        }

        g_dev = BluetoothLEDevice::FromIdAsync(deviceId).get();
        if (!g_dev) { SaveError(L"SubscribeCgxEeg: FromIdAsync null"); return false; }

        // Find CGX service
        auto svcRes = g_dev.GetGattServicesForUuidAsync(kCgxServiceUuid, BluetoothCacheMode::Cached).get();
        if (svcRes.Status() != GattCommunicationStatus::Success || svcRes.Services().Size() == 0) {
            // Try uncached once
            svcRes = g_dev.GetGattServicesForUuidAsync(kCgxServiceUuid, BluetoothCacheMode::Uncached).get();
            if (svcRes.Status() != GattCommunicationStatus::Success || svcRes.Services().Size() == 0) {
                SaveError(L"SubscribeCgxEeg: CGX service not found");
                return false;
            }
        }
        g_svc = svcRes.Services().GetAt(0);
        try {
            if (auto sess = g_svc.Session()) sess.MaintainConnection(true);
        }
        catch (...) {}
        // Helper to bind a characteristic
        auto bindChar = [&](guid const& cuuid, GattCharacteristic& out, event_token& tok)->bool {
            auto cres = g_svc.GetCharacteristicsForUuidAsync(cuuid, BluetoothCacheMode::Uncached).get();
            if (cres.Status() != GattCommunicationStatus::Success || cres.Characteristics().Size() == 0) {
                cres = g_svc.GetCharacteristicsForUuidAsync(cuuid, BluetoothCacheMode::Cached).get();
                if (cres.Status() != GattCommunicationStatus::Success || cres.Characteristics().Size() == 0)
                    return false;
            }
            auto ch = cres.Characteristics().GetAt(0);

            // Write CCCD = Notify
            auto status = ch.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify).get();
            if (status != GattCommunicationStatus::Success) return false;

            out = ch; // keep the same instance

            // Hook ValueChanged → stitched queue
            tok = out.ValueChanged([cuuid](auto const&, GattValueChangedEventArgs const& args) {
                auto buf = args.CharacteristicValue();
                auto len = buf ? buf.Length() : 0;
                if (len == 0) return;
                DataReader r = DataReader::FromBuffer(buf);
                std::vector<uint8_t> v(len);
                r.ReadBytes(winrt::array_view<uint8_t>(v));
                EnqueueAssembled(std::move(v));
            });
            return true;
        };

        bool ok1 = bindChar(kCgxChar1Uuid, g_ch1, g_tok1);
        bool ok2 = bindChar(kCgxChar2Uuid, g_ch2, g_tok2);
        if (!ok1 && !ok2) {
            SaveError(L"SubscribeCgxEeg: neither characteristic could be subscribed");
            return false;
        }

        g_curDeviceId = g_dev.DeviceInformation().Id(); // remember for PollData
        g_subscribed.store(true, std::memory_order_release);
        ClearError();
        return true;
    }
    catch (hresult_error const& ex) {
        SaveError(L"SubscribeCgxEeg: %s", ex.message().c_str());
        return false;
    }
    catch (...) {
        SaveError(L"SubscribeCgxEeg: unknown");
        return false;
    }
}

extern "C" __declspec(dllexport) bool __cdecl UnsubscribeCgxEeg(const wchar_t* /*deviceId*/, bool /*block*/) {
    try {
        if (g_subscribed.exchange(false)) {
            try {
                if (g_ch1) g_ch1.ValueChanged(g_tok1);
                if (g_ch2) g_ch2.ValueChanged(g_tok2);
            }
            catch (...) {}
        }
        g_tok1 = {}; g_tok2 = {};

        try {
            if (g_ch1) g_ch1.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::None).get();
        }
        catch (...) {}
        try {
            if (g_ch2) g_ch2.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::None).get();
        }
        catch (...) {}

        // NEW: close session (if any) *before* closing chars
        // Close the GATT session via the service, if available
        try {
            if (g_svc) {
                auto sess = g_svc.Session();   // Session hangs off the service
                if (sess) {
                    // GattSession implements IClosable, so Close() is available
                    sess.Close();
                }
            }
        }
        catch (...) {}

        // NEW: explicit Close() in leaf→root order
        CloseIfIClosable(g_ch1);
        CloseIfIClosable(g_ch2);
        CloseIfIClosable(g_svc);
        CloseIfIClosable(g_dev);
        { std::lock_guard<std::mutex> lk(g_dataMx); g_dataQ.clear(); g_queuedBytes = 0; }
        ClearError();
        RequestAssemblerReset();
        return true;
    }
    catch (hresult_error const& ex) { SaveError(L"UnsubscribeCgxEeg: %s", ex.message().c_str()); return false; }
    catch (...) { SaveError(L"UnsubscribeCgxEeg: unknown"); return false; }

}

extern "C" __declspec(dllexport) bool __cdecl PollData(BLEDataNative* out, bool /*block*/) {
    if (!out) return false;
    std::lock_guard<std::mutex> lk(g_dataMx);
    if (g_dataQ.empty()) return false;

    auto nc = std::move(g_dataQ.front());
    g_queuedBytes -= nc.bytes.size();
    g_dataQ.pop_front();

    // Fill fields
    wcsncpy_s(out->deviceId, _countof(out->deviceId), g_curDeviceId.c_str(), _TRUNCATE);
    // Use your known CGX UUIDs for convenience (as strings)
    wchar_t svcStr[] = L"{2456E1B9-26E2-8F83-E744-F34F01E9D701}";
    wchar_t chStr[64] = {};
    swprintf_s(chStr, L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        nc.charUuid.Data1, nc.charUuid.Data2, nc.charUuid.Data3,
        nc.charUuid.Data4[0], nc.charUuid.Data4[1], nc.charUuid.Data4[2], nc.charUuid.Data4[3],
        nc.charUuid.Data4[4], nc.charUuid.Data4[5], nc.charUuid.Data4[6], nc.charUuid.Data4[7]);

    wcsncpy_s(out->serviceUuid, _countof(out->serviceUuid), svcStr, _TRUNCATE);
    wcsncpy_s(out->characteristicUuid, _countof(out->characteristicUuid), chStr, _TRUNCATE);

    int n = (int)std::min<size_t>(nc.bytes.size(), _countof(out->buf));
    out->size = n;
    if (n > 0) memcpy(out->buf, nc.bytes.data(), n);
    ClearError();
    return true;
}
extern "C" __declspec(dllexport) bool __cdecl PollStreamChunk(StreamChunkNative* out, bool /*block*/) {
    if (!out) return false;
    std::lock_guard<std::mutex> lk(g_dataMx);
    if (g_dataQ.empty()) return false;

    auto nc = std::move(g_dataQ.front());
    g_queuedBytes -= nc.bytes.size();
    g_dataQ.pop_front();

    int n = (int)std::min<size_t>(nc.bytes.size(), _countof(out->data));
    out->size = n;
    out->timestamp100ns = nc.ts100ns;
    if (n > 0) memcpy(out->data, nc.bytes.data(), n);
    ClearError();
    return true;
}



