"""``encompute.Privacy``: what a fine-tuning run's differential privacy
protects, and how strongly.

Two levels:

- **Organization** (``privacy="standard"``, ``"strong"``, ``"maximum"``):
  each participant's whole update is clipped. The budget bounds what the
  adapter reveals about one hospital's contribution, not about one patient.
- **Patient** (``privacy="standard-patient"``, ``"strong-patient"``, or
  ``Privacy(unit="patient", ...)``): DP-SGD. Each patient's gradient is
  clipped inside the attested worker, patients are Poisson-sampled every
  round, and the coordinator adds noise to the securely aggregated sum.
  The budget bounds what the adapter reveals about any one patient.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import _native
from ._frontend import EncomputeError

ORGANIZATION_LEVELS = ("standard", "strong", "maximum")


@dataclass(frozen=True)
class Privacy:
    """Differential privacy for fine-tuning.

    ``Privacy(unit="patient", level="strong-patient")`` is DP-SGD at the
    level's budget and noise. ``epsilon``, ``delta`` and
    ``noise_multiplier`` override the level. ``sampling_rate`` is each
    patient's probability of being in a round's sample; by default it is
    the configured batch size over the smallest dataset's patients.
    ``per_example_clip`` bounds each patient's gradient (L2).
    """

    unit: str = "patient"
    level: str = "strong-patient"
    epsilon: Optional[float] = None
    delta: Optional[float] = None
    noise_multiplier: Optional[float] = None
    sampling_rate: Optional[float] = None
    per_example_clip: float = 1.0

    @staticmethod
    def of(privacy) -> "Privacy | str":
        """A level name or a ``Privacy``: organization levels stay names."""
        if isinstance(privacy, Privacy):
            privacy.resolve()
            return privacy
        if privacy in ORGANIZATION_LEVELS:
            return privacy
        if any(privacy == p[0] for p in _native.patient_privacy_presets()):
            return Privacy(level=privacy)
        names = ORGANIZATION_LEVELS + tuple(p[0] for p in _native.patient_privacy_presets())
        raise EncomputeError("ENC2203", f"privacy is one of {', '.join(names)}, "
                                        "or encompute.Privacy(...)")

    def resolve(self) -> tuple:
        """``(epsilon, delta, noise_multiplier)``."""
        if self.unit == "organization":
            raise EncomputeError(
                "ENC2203", "Privacy(...) is DP-SGD: its unit is inside a participant (patient, "
                           "user, record). For organization-level privacy use "
                           'privacy="standard", "strong" or "maximum"')
        presets = {p[0]: p for p in _native.patient_privacy_presets()}
        if self.level not in presets:
            raise EncomputeError("ENC2203", f"the DP-SGD level is one of {', '.join(presets)}")
        _, eps, delta, z = presets[self.level]
        eps = self.epsilon if self.epsilon is not None else eps
        delta = self.delta if self.delta is not None else delta
        z = self.noise_multiplier if self.noise_multiplier is not None else z
        if not (eps > 0 and 0 < delta < 1 and z > 0 and self.per_example_clip > 0):
            raise EncomputeError("ENC2203", "epsilon, noise and clip must be positive, "
                                            "delta in (0, 1)")
        if self.sampling_rate is not None and not 0 < self.sampling_rate < 1:
            raise EncomputeError("ENC2203", "sampling_rate must be in (0, 1)")
        return float(eps), float(delta), float(z)
