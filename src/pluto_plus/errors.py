"""Application errors with stable API semantics."""


class PlutoPlusError(RuntimeError):
    pass


class RadioNotFoundError(PlutoPlusError):
    pass


class RadioBusyError(PlutoPlusError):
    pass


class RevisionConflictError(PlutoPlusError):
    pass


class RadioConfigurationError(PlutoPlusError):
    pass


class RadioSetupRequiredError(RadioConfigurationError):
    """The radio is safely identified but requires canonical hardware setup."""


class ArtifactNotFoundError(PlutoPlusError):
    pass


class AnalyzerNotFoundError(PlutoPlusError):
    pass


class FirmwareUnavailableError(PlutoPlusError):
    pass


class FirmwareObjectNotFoundError(PlutoPlusError):
    pass
