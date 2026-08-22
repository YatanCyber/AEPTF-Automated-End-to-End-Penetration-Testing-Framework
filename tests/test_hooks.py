from aeptf.core.hooks import EventBus


def test_handler_receives_payload():
    bus = EventBus()
    received = []
    bus.on("test.event", lambda payload: received.append(payload))
    bus.emit("test.event", {"a": 1})
    assert received == [{"a": 1}]


def test_multiple_handlers_called_in_order():
    bus = EventBus()
    order = []
    bus.on("test.event", lambda p: order.append(1))
    bus.on("test.event", lambda p: order.append(2))
    bus.emit("test.event")
    assert order == [1, 2]


def test_off_removes_handler():
    bus = EventBus()
    received = []
    handler = lambda p: received.append(p)
    bus.on("test.event", handler)
    bus.off("test.event", handler)
    bus.emit("test.event", {"x": 1})
    assert received == []


def test_raising_handler_does_not_break_emit():
    bus = EventBus()
    called = []

    def bad_handler(payload):
        raise RuntimeError("boom")

    def good_handler(payload):
        called.append(payload)

    bus.on("test.event", bad_handler)
    bus.on("test.event", good_handler)
    bus.emit("test.event", {"ok": True})  # must not raise
    assert called == [{"ok": True}]


def test_emit_unknown_event_is_a_noop():
    bus = EventBus()
    bus.emit("nothing.subscribed")  # must not raise
