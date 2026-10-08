import PushCore
import UserNotifications

/// SPIKE reference for P4. Opens the protocol v2 section 9 sealed object that the relay forwards as the JSON
/// *string* in APNs key "o" (those exact bytes go to PushOpener). Every path delivers freshly built content: the
/// relay's title/subtitle/category/thread/sound/attachments/userInfo are never carried over, because whoever holds
/// the APNs key controls them (and can also skip the extension by omitting mutable-content).
final class NotificationService: UNNotificationServiceExtension {
    private let gate = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private let store = SpikeStore()

    /// Delivers exactly once, whichever of didReceive paths and the timeout gets here first.
    private func finish(_ c: UNNotificationContent) {
        gate.lock(); let h = handler; handler = nil; gate.unlock()
        h?(c)
    }

    static func generic() -> UNMutableNotificationContent {
        let c = UNMutableNotificationContent()
        c.title = "orch"; c.body = "New activity"; c.sound = .default
        return c
    }

    enum Outcome { case refuse(String), show(UNMutableNotificationContent, key: String, closed: Bool) }

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        gate.lock(); handler = contentHandler; gate.unlock()
        switch process(request.content.userInfo, now: Date()) {
        case .refuse(let why):
            orchLog.notice("NSE refuse why=\(why, privacy: .public)")
            store.appendLog(["res": "refuse", "why": why, "t": Int(Date().timeIntervalSince1970)])
            finish(Self.generic())
        case .show(let content, let key, let closed):
            orchLog.notice("NSE show")
            store.appendLog(["res": "show", "t": Int(Date().timeIntervalSince1970)])
            if closed { replaceDelivered(key: key, thenDeliver: content) } else { finish(content) }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        orchLog.error("NSE time expired")
        finish(Self.generic())                      // never the relay's alert
    }

    /// Everything before showing: material, lock, load table, section 9 rules, durable write. Fails closed.
    func process(_ userInfo: [AnyHashable: Any], now: Date) -> Outcome {
        guard let o = userInfo["o"] as? String else { return .refuse("no_o") }
        guard let keys = store.loadMaterial() else { return .refuse("no_material") }
        let raw = Data(o.utf8)
        do {
            return try store.withLock {
                var last = try store.loadLast()
                let nowMs = Int64(now.timeIntervalSince1970 * 1000)
                switch PushOpener.open(raw: raw, keys: keys, last: &last, nowMs: nowMs) {
                case .drop(let why): return .refuse(why)
                case .show(let p):
                    // `last` was loaded under the lock, so recording p.ts is already a merge to the maximum.
                    last = last.filter { $0.value >= nowMs - PushOpener.maxAgeMs - PushOpener.skewMs }
                    try store.saveLast(last)         // durable BEFORE anything is shown
                    guard let ws = try StrictJSON.parse(raw).object?["ws"]?.string else { return .refuse("shape") }
                    let c = UNMutableNotificationContent()
                    c.title = p.kind == "question.closed" ? "Answered" : "orch"
                    c.body = p.label
                    c.sound = .default
                    c.threadIdentifier = ws          // local only, set from the verified ws
                    let key = "\(ws)/\(p.id)"
                    c.userInfo = ["o": o, "orch_key": key]
                    return .show(c, key: key, closed: p.kind == "question.closed")
                }
            }
        } catch let e as StoreError { return .refuse(e.why) }
        catch { return .refuse("store") }
    }

    /// "Answered elsewhere": remove delivered notifications of the same (ws, id), then deliver this one.
    private func replaceDelivered(key: String, thenDeliver content: UNMutableNotificationContent) {
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { [weak self] delivered in
            let want = Data(key.utf8)
            let old = delivered.filter { ($0.request.content.userInfo["orch_key"] as? String).map { Data($0.utf8) == want } ?? false }
                .map(\.request.identifier)
            center.removeDeliveredNotifications(withIdentifiers: old)
            orchLog.notice("NSE replace removed=\(old.count, privacy: .public)")
            self?.store.appendLog(["res": "replace", "removed": old.count])
            self?.finish(content)
        }
    }
}
