import UIKit
import UserNotifications

/// Launch argument: `-nse-selftest <dir with *.apns>`. Feeds every payload through the real NotificationService
/// class (in this process, not in the extension process) and posts the resulting content as a local
/// notification whose identifier plays the role of `apns-collapse-id`. Needed because `simctl push` does not
/// start the extension (see docs/spikes/S2-apns-nse.md).
enum SelfTest {
    static func run(dir: String, done: @escaping () -> Void) {
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.hasSuffix(".apns") }.sorted()
        let center = UNUserNotificationCenter.current()
        var held: [NotificationService] = []
        func next(_ i: Int) {
            guard i < files.count else { done(); return }
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: dir + "/" + files[i])),
                  var payload = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { next(i + 1); return }
            payload.removeValue(forKey: "Simulator Target Bundle")
            let aps = payload["aps"] as? [String: Any] ?? [:]
            let alert = aps["alert"] as? [String: Any] ?? [:]
            let c = UNMutableNotificationContent()
            c.title = alert["title"] as? String ?? ""; c.body = alert["body"] as? String ?? ""
            c.threadIdentifier = aps["thread-id"] as? String ?? ""
            c.userInfo = payload
            // a real relay sends apns-collapse-id per question; here question and closed share one
            let collapse = files[i].contains("question") ? "cid-q-0167f4bf37be9ccc" : "cid-" + files[i]
            let req = UNNotificationRequest(identifier: collapse, content: c, trigger: nil)
            let nse = NotificationService(); held.append(nse)
            nse.didReceive(req) { out in
                orchLog.notice("selftest \(files[i], privacy: .public) -> title=\(out.title, privacy: .public) body=\(out.body, privacy: .public) collapse=\(collapse, privacy: .public)")
                center.add(UNNotificationRequest(identifier: collapse, content: out, trigger: nil)) { _ in
                    center.getDeliveredNotifications { ds in
                        orchLog.notice("selftest delivered now: \(ds.map { $0.request.identifier + "=" + $0.request.content.body }.joined(separator: " ; "), privacy: .public)")
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { next(i + 1) }
                    }
                }
            }
        }
        next(0)
    }
}
