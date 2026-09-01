"""Hybrid serial-attested IIO control plus direct-IP dual-RX capture adapter."""

from __future__ import annotations

from pluto_plus.direct_radio.ip_transport import DirectIpTransport
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import RadioDevice, SampleBlock
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport
from pluto_plus.rf_profile import RxLayoutExpectation


class DirectIpRadioDevice:
    """Use ordinary IIO for control and the direct-IP gadget for finite refills."""

    def __init__(self, control: RadioDevice, capture: DirectIpTransport) -> None:
        self._control = control
        self._capture = capture
        self._open = False

    @property
    def identity(self) -> RadioIdentity:
        base = self._control.identity
        return base.model_copy(
            update={
                "uri": f"direct-ip://{self._capture.host}:{self._capture.control_port}",
                "transport": Transport.DIRECT_IP,
            }
        )

    @property
    def capabilities(self) -> RadioCapabilities:
        return self._control.capabilities.model_copy(
            update={"receiver_channels": (0, 1), "supports_direct_capture": True}
        )

    def configure_rx_layout(self, expectation: RxLayoutExpectation | None) -> None:
        if expectation is not None and expectation.receiver_channels != (0, 1):
            raise RadioConfigurationError("direct-IP capture requires paired RX")
        configure_rx_layout = getattr(self._control, "configure_rx_layout", None)
        if not callable(configure_rx_layout):
            raise RadioConfigurationError("IIO control cannot select an RX layout")
        configure_rx_layout(expectation)

    def open(self) -> None:
        if self._open:
            raise RuntimeError("direct-IP radio is already open")
        self._control.open()
        try:
            settings = self._control.read_settings()
            if settings.channels != (0, 1):
                self._control.apply_settings(settings.model_copy(update={"channels": (0, 1)}))
            self._capture.open()
        except BaseException:
            self._control.close()
            raise
        self._open = True

    def close(self) -> None:
        self._capture.close()
        self._control.close()
        self._open = False

    def read_settings(self) -> RadioSettings:
        return self._control.read_settings()

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        if settings.channels != (0, 1):
            raise ValueError("direct-IP capture requires both receiver channels")
        return self._control.apply_settings(settings)

    def read_block(self, sample_count: int) -> SampleBlock:
        if not self._open:
            raise RuntimeError("direct-IP radio is not open")
        capture = self._capture.capture(sample_count)
        return SampleBlock(utc_ns=capture.utc_ns, samples=capture.samples)
