import SwiftUI
import UserNotifications

@main
struct OrchApp: App {
    @UIApplicationDelegateAdaptor(Delegate.self) var delegate
    var body: some Scene { WindowGroup { ContentView() } }
}

final class Delegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions o: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        let store = SpikeStore()
        // Provision the demo material into the shared container (what pairing would do on a real device).
        if let src = Bundle.main.url(forResource: "demo_material", withExtension: "json"), let dst = try? store.materialURL() {
            try? FileManager.default.removeItem(at: dst)
            try? FileManager.default.copyItem(at: src, to: dst)
        }
        orchLog.notice("app launched; group container: \(store.usesGroup, privacy: .public)")
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .provisional]) { ok, err in  // provisional: no prompt, so headless Simulator runs work
            orchLog.notice("notification authorization granted=\(ok, privacy: .public) err=\(String(describing: err), privacy: .public)")
        }
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "-nse-selftest"), i + 1 < args.count {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { SelfTest.run(dir: args[i + 1]) {} }
        }
        return true
    }

    // Show banners even when the app is in the foreground.
    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}

struct ContentView: View {
    @State private var log: [String] = []
    @State private var delivered: [String] = []
    var body: some View {
        let store = SpikeStore()
        NavigationStack {
            List {
                Section("Shared container") {
                    Text(store.usesGroup ? "App Group container: yes" : "App Group container: NO")
                    Text(store.dir?.path ?? "-").font(.caption2).textSelection(.enabled)
                }
                Section("Delivered notifications (\(delivered.count))") { ForEach(delivered, id: \.self) { Text($0).font(.caption) } }
                Section("NSE log (reasons only)") { ForEach(log, id: \.self) { Text($0).font(.caption2) } }
            }
            .navigationTitle("orch S2")
            .toolbar { Button("Refresh") { refresh() } }
            .onAppear(perform: refresh)
        }
    }
    func refresh() {
        let store = SpikeStore()
        log = ((try? String(contentsOf: store.logURL(), encoding: .utf8)) ?? "").split(separator: "\n").suffix(12).map(String.init)
        UNUserNotificationCenter.current().getDeliveredNotifications { ns in
            DispatchQueue.main.async { delivered = ns.map { "\($0.request.content.title) | \($0.request.content.body)" } }
        }
    }
}
