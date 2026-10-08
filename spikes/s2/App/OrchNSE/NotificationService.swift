import PushCore
import UserNotifications

/// Opens the protocol v2 section 9 sealed object in the APNs payload key "o". On any refusal the notification
/// keeps the generic text that the relay put in aps.alert: attacker-chosen content is never shown.
final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var best: UNMutableNotificationContent?
    private let store = SharedStore()

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        let content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        best = content
        let rid = request.identifier
        orchLog.notice("NSE didReceive id=\(rid, privacy: .public) group=\(self.store.usesGroup, privacy: .public)")

        let (result, source) = open(request.content.userInfo)
        switch result {
        case .show(let p):
            content.title = p.kind == "question.closed" ? "Answered" : "orch"
            content.body = p.label
            content.threadIdentifier = content.threadIdentifier   // keep the ws thread from aps.thread-id
            content.userInfo["orch_id"] = p.id
            content.userInfo["orch_kind"] = p.kind
            orchLog.notice("NSE show kind=\(p.kind, privacy: .public) id=\(p.id, privacy: .public) label=\(p.label, privacy: .public) material=\(source, privacy: .public)")
            record(["res": "show", "kind": p.kind, "id": p.id, "label": p.label, "rid": rid, "material": source])
            // "Answered elsewhere": drop the delivered notification(s) of the same question, then deliver this one.
            if p.kind == "question.closed" {
                replaceDelivered(id: p.id, thenDeliver: content)
                return
            }
        case .drop(let why):
            content.title = "orch"
            content.body = "New activity"                       // never attacker content
            orchLog.notice("NSE drop why=\(why, privacy: .public) material=\(source, privacy: .public)")
            record(["res": "drop", "why": why, "rid": rid, "material": source])
        }
        contentHandler(content)
    }

    override func serviceExtensionTimeWillExpire() {
        // Out of time: deliver whatever we have, which is the generic text unless a result was set.
        orchLog.error("NSE time expired")
        if let h = handler, let c = best { c.body = c.body.isEmpty ? "New activity" : c.body; h(c) }
    }

    private func open(_ userInfo: [AnyHashable: Any]) -> (PushOpener.Result, String) {
        guard let obj = userInfo["o"], JSONSerialization.isValidJSONObject(obj),
              let raw = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]),
              let m = store.loadMaterial(bundle: Bundle(for: NotificationService.self)) else { return (.drop("shape"), "-") }
        var last = store.loadLast()
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let r = PushOpener.open(raw: raw, keys: m.keys, last: &last, nowMs: now)
        if case .show = r { store.saveLast(last) }
        return (r, m.source)
    }

    private func replaceDelivered(id: String, thenDeliver content: UNMutableNotificationContent) {
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { [weak self] delivered in
            let old = delivered.filter { $0.request.content.userInfo["orch_id"] as? String == id }.map(\.request.identifier)
            orchLog.notice("NSE replace: removing \(old.count, privacy: .public) delivered with orch_id=\(id, privacy: .public)")
            self?.record(["res": "replace", "removed": old.count, "id": id])
            center.removeDeliveredNotifications(withIdentifiers: old)
            self?.handler?(content)
        }
    }

    private func record(_ d: [String: Any]) {
        var d = d; d["t"] = Int(Date().timeIntervalSince1970)
        store.appendLog(d)
    }
}
