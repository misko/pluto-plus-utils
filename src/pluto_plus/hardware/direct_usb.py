"""Hybrid serial-attested IIO control plus direct-USB dual-RX capture."""

from __future__ import annotations

from pluto_plus.direct_radio.usb_transport import DirectUsbTransport
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import RadioDevice, SampleBlock
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport
from pluto_plus.rf_profile import RxLayoutExpectation


class DirectUsbRadioDevice:
    """Use ordinary IIO for control and a pinned gadget interface for capture."""

    def __init__(self, control: RadioDevice, capture: DirectUsbTransport) -> None:
        self._control = control
        self._capture = capture
        self._open = False

    @property
    def identity(self) -> RadioIdentity:
        base = self._control.identity
        return base.model_copy(
            update={
                "uri": f"direct-usb://{self._capture.requested_serial or 'port-path'}",
                "transport": Transport.DIRECT_USB,
            }
        )

    @property
    def capabilities(self) -> RadioCapabilities:
        return self._control.capabilities.model_copy(
            update={"receiver_channels": (0, 1), "supports_direct_capture": True}
        )

    def configure_rx_layout(self, expectation: RxLayoutExpectation | None) -> None:
        if expectation is not None and expectation.receiver_channels != (0, 1):
            raise RadioConfigurationError("direct-USB capture requires paired RX")
        configure_rx_layout = getattr(self._control, "configure_rx_layout", None)
        if not callable(configure_rx_layout):
            raise RadioConfigurationError("IIO control cannot select an RX layout")
        configure_rx_layout(expectation)

    def open(self) -> None:
        if self._open:
            raise RuntimeError("direct-USB radio is already open")
        self._control.open()
        try:
            settings = self._control.read_settings()
            if settings.channels != (0, 1):
                self._control.apply_settings(settings.model_copy(update={"channels": (0, 1)}))
            self._capture.open()
            if self._capture.identity.serial != self._control.identity.serial:
                raise RuntimeError(
                    "direct-USB gadget serial does not match the IIO control serial"
                )
        except BaseException:
            self._capture.close()
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
            raise ValueError("direct-USB capture requires both receiver channels")
        return self._control.apply_settings(settings)

    def read_block(self, sample_count: int) -> SampleBlock:
        if not self._open:
            raise RuntimeError("direct-USB radio is not open")
        capture = self._capture.capture(sample_count)
        return SampleBlock(utc_ns=capture.utc_ns, samples=capture.samples)
