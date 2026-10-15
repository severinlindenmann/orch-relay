import UIKit
import UserNotifications

/// Launch argument: `-nse-selftest <dir with *.apns>`. Feeds every payload through the real NotificationService
/// class, compiled into the app and called directly (NOT the extension process: sandbox, entitlements and the
/// extension point are not exercised). The request identifier is chosen by this harness (it plays the role of
/// apns-collapse-id for the local re-add), so replacement here does not test APNs collapse. Results go to
/// `selftest-result.jsonl` in the group container; os_log gets no content.
enum SelfTest {
    static func run(dir: String, done: @escaping () -> Void) {
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.hasSuffix(".apns") }.sorted()
        let center = UNUserNotificationCenter.current()
        let store = SpikeStore()
        if let u = try? store.selftestURL() { try? FileManager.default.removeItem(at: u) }
        var held: [NotificationService] = []

        func next(_ i: Int) {
            guard i < files.count else { raceCheck(files: files, dir: dir, held: &held, store: store, done: done); return }
            guard let req = request(dir: dir, file: files[i]) else { next(i + 1); return }
            let nse = NotificationService(); held.append(nse)
            nse.didReceive(req) { out in
                center.add(UNNotificationRequest(identifier: req.identifier, content: out, trigger: nil)) { _ in
                    center.getDeliveredNotifications { ds in
                        store.appendSelfTest([
                            "file": files[i], "title": out.title, "body": out.body, "subtitle": out.subtitle,
                            "category": out.categoryIdentifier, "thread": out.threadIdentifier,
                            "relay_userinfo_carried": out.userInfo["relay_marker"] != nil,
                            "delivered": ds.map { $0.request.identifier + "=" + $0.request.content.body }.sorted(),
                        ])
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { next(i + 1) }
                    }
                }
            }
        }
        next(0)
    }

    /// Builds the request a hostile relay could send: marker subtitle/category/thread/userInfo around the `o` string.
    static func request(dir: String, file: String) -> UNNotificationRequest? {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: dir + "/" + file)),
              var payload = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return nil }
        payload.removeValue(forKey: "Simulator Target Bundle")
        let alert = (payload["aps"] as? [String: Any])?["alert"] as? [String: Any] ?? [:]
        let c = UNMutableNotificationContent()
        c.title = alert["title"] as? String ?? ""; c.body = alert["body"] as? String ?? ""
        c.subtitle = "RELAY SUBTITLE"; c.categoryIdentifier = "RELAY_CATEGORY"; c.threadIdentifier = "relay-thread"
        c.userInfo = payload.merging(["relay_marker": "x"]) { a, _ in a }
        let collapse = file.contains("question") ? "cid-question" : "cid-" + file   // harness-chosen identifier
        return UNNotificationRequest(identifier: collapse, content: c, trigger: nil)
    }

    /// The content handler must be called exactly once even if the timeout fires right after didReceive.
    static func raceCheck(files: [String], dir: String, held: inout [NotificationService], store: SpikeStore, done: @escaping () -> Void) {
        guard let f = files.last, let req = request(dir: dir, file: f) else { done(); return }
        let nse = NotificationService(); held.append(nse)
        let calls = NSLock(); var n = 0
        nse.didReceive(req) { _ in calls.lock(); n += 1; calls.unlock() }
        nse.serviceExtensionTimeWillExpire()
        nse.serviceExtensionTimeWillExpire()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            calls.lock(); store.appendSelfTest(["file": "race_timeout_x2", "handler_calls": n]); calls.unlock()
            orchLog.notice("selftest done")
            done()
        }
    }
}
