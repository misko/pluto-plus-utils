"""Read-only entry-point inventory; presence never diagnoses a failed component."""

from pathlib import Path


def discover(
    *, serial_root: Path = Path("/dev/serial/by-id"), usb_root: Path = Path("/sys/bus/usb/devices")
) -> dict[str, object]:
    serial = []
    if serial_root.is_dir():
        for path in sorted(serial_root.iterdir()):
            try:
                serial.append({"adapter": str(path), "endpoint": str(path.resolve(strict=True))})
            except OSError:
                continue
    usb = []
    if usb_root.is_dir():
        for path in sorted(usb_root.iterdir()):
            try:
                vendor = (path / "idVendor").read_text().strip()
                product = (path / "idProduct").read_text().strip()
            except OSError:
                continue
            if vendor == "0456" and product in {"b673", "b674"}:
                usb.append(
                    {
                        "physical_path": str(path),
                        "vendor": vendor,
                        "product": product,
                        "mode": "runtime" if product == "b673" else "dfu",
                        "selected": False,
                    }
                )
    return {
        "serial_endpoints": serial,
        "usb_radios": usb,
        "selected_target": None,
        "network": "not probed; use an explicit physically correlated target",
        "sd_uboot": "unknown until a qualified bound console observation",
        "jtag": "documented handoff only; automation is not implemented",
        "diagnosis": "missing USB or console evidence does not identify a failed component",
    }
