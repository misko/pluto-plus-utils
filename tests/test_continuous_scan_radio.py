from types import SimpleNamespace

import pytest
from test_continuous_scan import setup

from pluto_plus import continuous_scan_radio as radio


@pytest.mark.parametrize("hook_failure", [False, True])
def test_prepare_hook_open_order_and_failure_restoration(monkeypatch, hook_failure):
    order = []
    preparation = SimpleNamespace(setup=setup())

    class Client:
        def capabilities(self):
            order.append("caps")

        def start(self, setup, **_):
            assert setup is preparation.setup
            order.append("OPENM")
            return object()

    def prepare(*_, **__):
        order.append("prepare")
        return preparation

    def restore(*_, **__):
        order.append("restore")

    def hook(value):
        assert value is preparation
        order.append("hook")
        if hook_failure:
            raise RuntimeError("fixture hook failed")

    monkeypatch.setattr(radio, "prepare_adaptive_scan_radio", prepare)
    monkeypatch.setattr(radio, "restore_adaptive_scan_radio", restore)
    arguments = dict(client_factory=lambda _: Client(), before_start_hook=hook)
    if hook_failure:
        with pytest.raises(RuntimeError, match="fixture hook failed"):
            radio.ContinuousRadioOwner.start("ip:192.168.1.15", "serial", object(), **arguments)
        assert order == ["caps", "prepare", "hook", "restore"]
    else:
        radio.ContinuousRadioOwner.start("ip:192.168.1.15", "serial", object(), **arguments)
        assert order == ["caps", "prepare", "hook", "OPENM"]
