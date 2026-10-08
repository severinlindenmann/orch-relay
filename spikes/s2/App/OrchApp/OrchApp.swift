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
        let store = SharedStore()
        // Provision the demo material into the shared container (what pairing would do on a real device).
        if let src = Bundle.main.url(forResource: "demo_material", withExtension: "json") {
            try? FileManager.default.removeItem(at: store.materialURL)
            try? FileManager.default.copyItem(at: src, to: store.materialURL)
        }
        orchLog.notice("app launched; shared dir uses group container: \(store.usesGroup, privacy: .public) path: \(store.dir.path, privacy: .public)")
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .provisional]) { ok, err in  // provisional: no prompt, so headless Simulator runs work
            orchLog.notice("notification authorization granted=\(ok, privacy: .public) err=\(String(describing: err), privacy: .public)")
        }
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "-nse-selftest"), i + 1 < args.count {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { SelfTest.run(dir: args[i + 1]) { orchLog.notice("selftest done") } }
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
        let store = SharedStore()
        NavigationStack {
            List {
                Section("Shared container") {
                    Text(store.usesGroup ? "App Group container: yes" : "App Group container: NO (private Library)")
                    Text(store.dir.path).font(.caption2).textSelection(.enabled)
                }
                Section("Delivered notifications (\(delivered.count))") { ForEach(delivered, id: \.self) { Text($0).font(.caption) } }
                Section("NSE log") { ForEach(log, id: \.self) { Text($0).font(.caption2) } }
            }
            .navigationTitle("orch S2")
            .toolbar { Button("Refresh") { refresh() } }
            .onAppear(perform: refresh)
        }
    }
    func refresh() {
        let store = SharedStore()
        log = ((try? String(contentsOf: store.logURL, encoding: .utf8)) ?? "").split(separator: "\n").suffix(12).map(String.init)
        UNUserNotificationCenter.current().getDeliveredNotifications { ns in
            DispatchQueue.main.async { delivered = ns.map { "\($0.request.content.title) | \($0.request.content.body)" } }
        }
    }
}
